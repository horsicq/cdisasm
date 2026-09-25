#include "x86_decoder.h"
#include "x86_opcode_tables.h"

#define X86_MAX_OPERANDS CDISASM_MAX_OPERANDS

#define X86_CAP_80186 (UINT64_C(1) << 0)
#define X86_CAP_80286 (UINT64_C(1) << 1)
#define X86_CAP_80386 (UINT64_C(1) << 2)
#define X86_CAP_80486 (UINT64_C(1) << 3)
#define X86_CAP_PENTIUM (UINT64_C(1) << 4)
#define X86_CAP_P6 (UINT64_C(1) << 5)
#define X86_CAP_MMX (UINT64_C(1) << 6)
#define X86_CAP_SEP (UINT64_C(1) << 7)
#define X86_CAP_PAUSE (UINT64_C(1) << 8)
#define X86_CAP_AMD64 (UINT64_C(1) << 9)
#define X86_CAP_SMX (UINT64_C(1) << 10)
#define X86_CAP_POPCNT (UINT64_C(1) << 11)
#define X86_CAP_LZCNT (UINT64_C(1) << 12)
#define X86_CAP_BMI1 (UINT64_C(1) << 13)
#define X86_CAP_CET_IBT (UINT64_C(1) << 14)
#define X86_CAP_CPUID (UINT64_C(1) << 15)
#define X86_CAP_VMX (UINT64_C(1) << 16)
#define X86_CAP_INVEPT (UINT64_C(1) << 17)
#define X86_CAP_INVVPID (UINT64_C(1) << 18)
#define X86_CAP_VMFUNC (UINT64_C(1) << 19)
#define X86_CAP_SVM (UINT64_C(1) << 20)
#define X86_CAP_SEV_ES (UINT64_C(1) << 21)
#define X86_CAP_3DNOW (UINT64_C(1) << 22)
#define X86_CAP_3DNOW_EXT (UINT64_C(1) << 23)
#define X86_CAP_PREFETCH (UINT64_C(1) << 24)
#define X86_CAP_PREFETCHW (UINT64_C(1) << 25)
#define X86_CAP_UD0 (UINT64_C(1) << 26)
#define X86_CAP_UD1 (UINT64_C(1) << 27)
#define X86_CAP_HLE (UINT64_C(1) << 28)
#define X86_CAP_AVX (UINT64_C(1) << 29)
#define X86_CAP_SSE (UINT64_C(1) << 30)
#define X86_CAP_SSE2 (UINT64_C(1) << 31)
#define X86_CAP_SSE3 (UINT64_C(1) << 32)
#define X86_CAP_SSSE3 (UINT64_C(1) << 33)
#define X86_CAP_SSE41 (UINT64_C(1) << 34)
#define X86_CAP_SSE4A (UINT64_C(1) << 35)
#define X86_CAP_SSE42 (UINT64_C(1) << 36)
#define X86_CAP_X87 (UINT64_C(1) << 37)
#define X86_CAP_X87_287 (UINT64_C(1) << 38)
#define X86_CAP_X87_387 (UINT64_C(1) << 39)
#define X86_CAP_AVX2 (UINT64_C(1) << 40)
#define X86_CAP_CLFLUSH (UINT64_C(1) << 41)
#define X86_CAP_CLFLUSHOPT (UINT64_C(1) << 42)
#define X86_CAP_CLWB (UINT64_C(1) << 43)
#define X86_CAP_RDPID (UINT64_C(1) << 44)
#define X86_CAP_SERIALIZE (UINT64_C(1) << 45)
#define X86_CAP_MOVDIRI (UINT64_C(1) << 46)
#define X86_CAP_MOVDIR64B (UINT64_C(1) << 47)
#define X86_CAP_WBNOINVD (UINT64_C(1) << 48)
#define X86_CAP_FXSR (UINT64_C(1) << 49)
#define X86_CAP_MONITOR (UINT64_C(1) << 50)
#define X86_CAP_RDTSCP (UINT64_C(1) << 51)
#define X86_CAP_CMPXCHG16B (UINT64_C(1) << 52)
#define X86_CAP_ALL UINT64_MAX

static int is_vpunpck_integer_opcode(uint8_t opcode)
{
    return opcode == UINT8_C(0x60) || opcode == UINT8_C(0x61)
        || opcode == UINT8_C(0x62) || opcode == UINT8_C(0x68)
        || opcode == UINT8_C(0x69) || opcode == UINT8_C(0x6a)
        || opcode == UINT8_C(0x6c) || opcode == UINT8_C(0x6d);
}

static int is_classic_packed_compare_opcode(uint8_t opcode)
{
    return opcode == UINT8_C(0x64) || opcode == UINT8_C(0x65)
        || opcode == UINT8_C(0x66) || opcode == UINT8_C(0x74)
        || opcode == UINT8_C(0x75) || opcode == UINT8_C(0x76);
}

static int is_classic_modular_add_sub_opcode(uint8_t opcode)
{
    return opcode == UINT8_C(0xd4)
        || (opcode >= UINT8_C(0xf8) && opcode <= UINT8_C(0xfe));
}

static int is_packed_integer_minmax_opcode(
    uint8_t map_select,
    uint8_t opcode)
{
    return (map_select == UINT8_C(1)
            && (opcode == UINT8_C(0xda) || opcode == UINT8_C(0xde)
                || opcode == UINT8_C(0xea) || opcode == UINT8_C(0xee)))
        || (map_select == UINT8_C(2)
            && opcode >= UINT8_C(0x38) && opcode <= UINT8_C(0x3f));
}

static int is_vpsign_integer_opcode(uint8_t opcode)
{
    return opcode == UINT8_C(0x08) || opcode == UINT8_C(0x09)
        || opcode == UINT8_C(0x0a);
}

static int is_horizontal_integer_opcode(uint8_t opcode)
{
    return opcode == UINT8_C(0x01) || opcode == UINT8_C(0x02)
        || opcode == UINT8_C(0x03) || opcode == UINT8_C(0x05)
        || opcode == UINT8_C(0x06) || opcode == UINT8_C(0x07);
}

static int is_vphminposuw_opcode(uint8_t opcode)
{
    return opcode == UINT8_C(0x41);
}

static int is_vpmovsx_opcode(uint8_t opcode)
{
    return opcode >= UINT8_C(0x20) && opcode <= UINT8_C(0x25);
}

static int is_vpmovzx_opcode(uint8_t opcode)
{
    return opcode >= UINT8_C(0x30) && opcode <= UINT8_C(0x35);
}

static int is_vpinsr_vex_opcode(uint8_t map_select, uint8_t opcode)
{
    return (map_select == UINT8_C(1) && opcode == UINT8_C(0xc4))
        || (map_select == UINT8_C(3)
            && (opcode == UINT8_C(0x20) || opcode == UINT8_C(0x22)));
}

static int is_vpextr_vex_opcode(uint8_t map_select, uint8_t opcode)
{
    return (map_select == UINT8_C(1) && opcode == UINT8_C(0xc5))
        || (map_select == UINT8_C(3)
            && opcode >= UINT8_C(0x14) && opcode <= UINT8_C(0x16));
}

#if USE_EXTRA_OPCODES
/*
 * Modern ISA families are keyed by their stable public group IDs.  Keeping
 * them in two words avoids exhausting the historical capability mask and
 * keeps independent gates for every optional family implemented below.
 */
#define X86_EXTRA_GROUP_BASE CDISASM_X86_GROUP_AESNI
#define X86_EXTRA_GROUP_HIGH_BASE \
    ((cdisasm_x86_group_id)(X86_EXTRA_GROUP_BASE + UINT16_C(64)))
#define X86_EXTRA_GROUP_LAST CDISASM_X86_GROUP_AVX10_MOVRS_512
#define X86_EXTRA_CAP(group_) \
    (UINT64_C(1) << ((unsigned int)(group_) - X86_EXTRA_GROUP_BASE))
#define X86_EXTRA_CAP_HIGH(group_) \
    (UINT64_C(1) << ((unsigned int)(group_) - X86_EXTRA_GROUP_HIGH_BASE))
#define X86_EXTRA_CAP_ALL UINT64_MAX
_Static_assert(
    X86_EXTRA_GROUP_LAST - X86_EXTRA_GROUP_BASE < 128,
    "x86 optional capability groups must fit in two 64-bit profile words");
#endif

#define X86_CAPS_86 UINT64_C(0)
#define X86_CAPS_186 X86_CAP_80186
#define X86_CAPS_286 (X86_CAPS_186 | X86_CAP_80286)
#define X86_CAPS_386 (X86_CAPS_286 | X86_CAP_80386)
#define X86_CAPS_486 \
    (X86_CAPS_386 | X86_CAP_80486 | X86_CAP_X87 \
        | X86_CAP_X87_287 | X86_CAP_X87_387)
#define X86_CAPS_486_CPUID (X86_CAPS_486 | X86_CAP_CPUID)
#define X86_CAPS_PENTIUM (X86_CAPS_486_CPUID | X86_CAP_PENTIUM)
#define X86_CAPS_P6 (X86_CAPS_PENTIUM | X86_CAP_P6)
#define X86_CAPS_PENTIUM_PRO (X86_CAPS_P6 | X86_CAP_UD0 | X86_CAP_UD1)
#define X86_CAPS_PENTIUM_MMX (X86_CAPS_PENTIUM | X86_CAP_MMX)
#define X86_CAPS_PENTIUM_II \
    (X86_CAPS_P6 | X86_CAP_MMX | X86_CAP_SEP | X86_CAP_UD1 \
        | X86_CAP_FXSR)
#define X86_CAPS_PENTIUM_III (X86_CAPS_PENTIUM_II | X86_CAP_SSE)
#define X86_CAPS_PENTIUM_4 \
    (X86_CAPS_PENTIUM_III | X86_CAP_SSE2 | X86_CAP_PAUSE | X86_CAP_UD0 \
        | X86_CAP_CLFLUSH)
#define X86_CAPS_AMD64 \
    (X86_CAPS_P6 | X86_CAP_MMX | X86_CAP_SEP | X86_CAP_PAUSE \
        | X86_CAP_AMD64 | X86_CAP_SSE | X86_CAP_SSE2 | X86_CAP_CLFLUSH \
        | X86_CAP_FXSR | X86_CAP_RDTSCP | X86_CAP_CMPXCHG16B)
#define X86_CAPS_K6_2 \
    (X86_CAPS_PENTIUM_MMX | X86_CAP_3DNOW \
        | X86_CAP_PREFETCH | X86_CAP_PREFETCHW)
#define X86_CAPS_ATHLON_64 \
    (X86_CAPS_AMD64 | X86_CAP_3DNOW | X86_CAP_3DNOW_EXT \
        | X86_CAP_PREFETCH | X86_CAP_PREFETCHW)
#define X86_CAPS_INTEL64 (X86_CAPS_PENTIUM_4 | X86_CAP_AMD64)
#define X86_CAPS_PRESCOTT \
    (X86_CAPS_INTEL64 | X86_CAP_SSE3 | X86_CAP_MONITOR \
        | X86_CAP_CMPXCHG16B)
#define X86_CAPS_INTEL_VTX (X86_CAPS_PRESCOTT | X86_CAP_VMX)
#define X86_CAPS_AMD_V \
    (X86_CAPS_ATHLON_64 | X86_CAP_SVM | X86_CAP_SSE3)
#define X86_CAPS_CORE_2 \
    (X86_CAPS_INTEL_VTX | X86_CAP_SMX | X86_CAP_SSSE3)
#define X86_CAPS_PENRYN (X86_CAPS_CORE_2 | X86_CAP_SSE41)
#define X86_CAPS_BARCELONA \
    (X86_CAPS_AMD_V | X86_CAP_POPCNT | X86_CAP_LZCNT \
        | X86_CAP_SSE3 | X86_CAP_SSE4A)
#define X86_CAPS_BULLDOZER \
    (X86_CAPS_AMD64 | X86_CAP_SVM | X86_CAP_POPCNT | X86_CAP_LZCNT \
        | X86_CAP_PREFETCH | X86_CAP_PREFETCHW | X86_CAP_AVX \
        | X86_CAP_SSE3 | X86_CAP_SSSE3 | X86_CAP_SSE41 \
        | X86_CAP_SSE4A | X86_CAP_SSE42 | X86_CAP_MONITOR)
#define X86_CAPS_NEHALEM \
    (X86_CAPS_PENRYN | X86_CAP_INVEPT | X86_CAP_INVVPID \
        | X86_CAP_POPCNT | X86_CAP_SSE42 | X86_CAP_RDTSCP)
#define X86_CAPS_SANDY_BRIDGE (X86_CAPS_NEHALEM | X86_CAP_AVX)
#define X86_CAPS_HASWELL \
    (X86_CAPS_SANDY_BRIDGE | X86_CAP_VMFUNC | X86_CAP_LZCNT | X86_CAP_BMI1 \
        | X86_CAP_HLE | X86_CAP_AVX2)
#define X86_CAPS_BROADWELL (X86_CAPS_HASWELL | X86_CAP_PREFETCHW)
#define X86_CAPS_ZEN (X86_CAPS_BULLDOZER | X86_CAP_BMI1 | X86_CAP_AVX2)
/*
 * Exact low-end Intel SKUs documented with SSE4.2 but without AVX.  Keep the
 * mask conservative: product-family ancestry must not silently restore AVX,
 * HLE, BMI1/LZCNT, SMX, CET, or virtualization subfeatures beyond the
 * explicitly listed VMX/INVEPT/VMFUNC capabilities below.
 */
#define X86_CAPS_LOWEND_SSE42 \
    (X86_CAPS_PRESCOTT | X86_CAP_VMX | X86_CAP_INVEPT \
        | X86_CAP_POPCNT | X86_CAP_SSSE3 \
        | X86_CAP_SSE41 | X86_CAP_SSE42)
#define X86_CAPS_LOWEND_ATOM_SSE42 \
    (X86_CAPS_LOWEND_SSE42 | X86_CAP_PREFETCHW | X86_CAP_VMFUNC)

typedef struct x86_modrm {
    uint8_t mod;
    uint8_t reg3;
    uint8_t rm3;
    uint8_t reg;
    uint8_t rm;
    uint8_t is_register;
    int base;
    int index;
    unsigned int scale;
    int rip_relative;
    int absolute;
    int has_displacement;
    int64_t displacement;
    uint64_t displacement_raw;
} x86_modrm;

typedef struct x86_operand {
    uint8_t type;
    cdisasm_x86_reg_id reg;
    cdisasm_x86_reg_id base_reg;
    cdisasm_x86_reg_id index_reg;
    uint8_t size;
    uint8_t scale;
    cdisasm_x86_reg_id segment_reg;
    uint8_t flags;
    uint64_t address;
    uint64_t imm;
    uint8_t resolve_pc_address;
    uint8_t access;
    cdisasm_x86_broadcast broadcast;
} x86_operand;

typedef struct x86_decoder {
    const uint8_t *code;
    size_t code_size;
    size_t position;
    uint64_t address;
    cdisasm_mode mode;
    cdisasm_cpu_id cpu_id;
    uint64_t cpu_caps;
    uint64_t required_caps;
#if USE_EXTRA_OPCODES
    uint64_t cpu_extra_caps;
    uint64_t cpu_extra_caps_high;
    uint64_t required_extra_caps;
    uint64_t required_extra_caps_high;
    uint64_t required_extra_any_caps;
    uint64_t required_extra_any_caps_high;
    uint64_t used_extra_groups;
    uint64_t used_extra_groups_high;
    uint8_t used_avx_ne_convert;
    uint8_t used_rao_int;
    uint8_t used_user_msr;
    uint8_t used_msrlist;
    uint8_t used_msr_imm;
    uint8_t used_wrmsrns;
#endif
    cdisasm_status error;

    uint32_t prefix_flags;
    uint8_t lock_prefix;
    uint8_t repeat_prefix;
    uint8_t segment_prefix;
    uint8_t rex;
    uint8_t rex_present;
    uint8_t rex2_present;
    uint8_t rex2_map;
    uint8_t modrm_reg_high;
    uint8_t modrm_rm_high;
    uint8_t address_base_high;
    uint8_t address_index_high;
    uint8_t operand_override;
    uint8_t address_override;
    uint8_t lock_allowed;
    uint8_t wait_prefix;

    unsigned int operand_bits;
    unsigned int address_bits;

    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    x86_operand operand[X86_MAX_OPERANDS];
    unsigned int operand_count;
    uint32_t groups;
    uint64_t branch_target;
    cdisasm_x86_reg_id mask_reg;
    cdisasm_x86_mask_mode mask_mode;
    cdisasm_x86_rounding_mode rounding;
    cdisasm_x86_sae sae;
    cdisasm_x86_encoding encoding;
} x86_decoder;

static const cdisasm_x86_name_id jump_condition_name[16] = {
    CDISASM_X86_NAME_JO, CDISASM_X86_NAME_JNO,
    CDISASM_X86_NAME_JB, CDISASM_X86_NAME_JAE,
    CDISASM_X86_NAME_JE, CDISASM_X86_NAME_JNE,
    CDISASM_X86_NAME_JBE, CDISASM_X86_NAME_JA,
    CDISASM_X86_NAME_JS, CDISASM_X86_NAME_JNS,
    CDISASM_X86_NAME_JP, CDISASM_X86_NAME_JNP,
    CDISASM_X86_NAME_JL, CDISASM_X86_NAME_JGE,
    CDISASM_X86_NAME_JLE, CDISASM_X86_NAME_JG
};

static const cdisasm_x86_name_id move_condition_name[16] = {
    CDISASM_X86_NAME_CMOVO, CDISASM_X86_NAME_CMOVNO,
    CDISASM_X86_NAME_CMOVB, CDISASM_X86_NAME_CMOVAE,
    CDISASM_X86_NAME_CMOVE, CDISASM_X86_NAME_CMOVNE,
    CDISASM_X86_NAME_CMOVBE, CDISASM_X86_NAME_CMOVA,
    CDISASM_X86_NAME_CMOVS, CDISASM_X86_NAME_CMOVNS,
    CDISASM_X86_NAME_CMOVP, CDISASM_X86_NAME_CMOVNP,
    CDISASM_X86_NAME_CMOVL, CDISASM_X86_NAME_CMOVGE,
    CDISASM_X86_NAME_CMOVLE, CDISASM_X86_NAME_CMOVG
};

static const cdisasm_x86_name_id apx_move_condition_name[16] = {
    CDISASM_X86_NAME_CMOVO, CDISASM_X86_NAME_CMOVNO,
    CDISASM_X86_NAME_CMOVB, CDISASM_X86_NAME_CMOVNB,
    CDISASM_X86_NAME_CMOVZ, CDISASM_X86_NAME_CMOVNZ,
    CDISASM_X86_NAME_CMOVBE, CDISASM_X86_NAME_CMOVNBE,
    CDISASM_X86_NAME_CMOVS, CDISASM_X86_NAME_CMOVNS,
    CDISASM_X86_NAME_CMOVP, CDISASM_X86_NAME_CMOVNP,
    CDISASM_X86_NAME_CMOVL, CDISASM_X86_NAME_CMOVNL,
    CDISASM_X86_NAME_CMOVLE, CDISASM_X86_NAME_CMOVNLE
};

static const cdisasm_x86_name_id set_condition_name[16] = {
    CDISASM_X86_NAME_SETO, CDISASM_X86_NAME_SETNO,
    CDISASM_X86_NAME_SETB, CDISASM_X86_NAME_SETAE,
    CDISASM_X86_NAME_SETE, CDISASM_X86_NAME_SETNE,
    CDISASM_X86_NAME_SETBE, CDISASM_X86_NAME_SETA,
    CDISASM_X86_NAME_SETS, CDISASM_X86_NAME_SETNS,
    CDISASM_X86_NAME_SETP, CDISASM_X86_NAME_SETNP,
    CDISASM_X86_NAME_SETL, CDISASM_X86_NAME_SETGE,
    CDISASM_X86_NAME_SETLE, CDISASM_X86_NAME_SETG
};

/* XED's pinned APX N3 catalog uses the architecturally equivalent N/Z
 * spellings for six conditions; retain those canonical identities so exact
 * IFORM evidence is not credited through an alias. */
static const cdisasm_x86_name_id apx_set_condition_name[16] = {
    CDISASM_X86_NAME_SETO, CDISASM_X86_NAME_SETNO,
    CDISASM_X86_NAME_SETB, CDISASM_X86_NAME_SETNB,
    CDISASM_X86_NAME_SETZ, CDISASM_X86_NAME_SETNZ,
    CDISASM_X86_NAME_SETBE, CDISASM_X86_NAME_SETNBE,
    CDISASM_X86_NAME_SETS, CDISASM_X86_NAME_SETNS,
    CDISASM_X86_NAME_SETP, CDISASM_X86_NAME_SETNP,
    CDISASM_X86_NAME_SETL, CDISASM_X86_NAME_SETNL,
    CDISASM_X86_NAME_SETLE, CDISASM_X86_NAME_SETNLE
};

static const cdisasm_x86_name_id string_instruction_name[5][4] = {
    {
        CDISASM_X86_NAME_MOVSB, CDISASM_X86_NAME_MOVSW,
        CDISASM_X86_NAME_MOVSD, CDISASM_X86_NAME_MOVSQ
    },
    {
        CDISASM_X86_NAME_CMPSB, CDISASM_X86_NAME_CMPSW,
        CDISASM_X86_NAME_CMPSD, CDISASM_X86_NAME_CMPSQ
    },
    {
        CDISASM_X86_NAME_STOSB, CDISASM_X86_NAME_STOSW,
        CDISASM_X86_NAME_STOSD, CDISASM_X86_NAME_STOSQ
    },
    {
        CDISASM_X86_NAME_LODSB, CDISASM_X86_NAME_LODSW,
        CDISASM_X86_NAME_LODSD, CDISASM_X86_NAME_LODSQ
    },
    {
        CDISASM_X86_NAME_SCASB, CDISASM_X86_NAME_SCASW,
        CDISASM_X86_NAME_SCASD, CDISASM_X86_NAME_SCASQ
    }
};

static const cdisasm_x86_name_id string_io_name[2][3] = {
    {
        CDISASM_X86_NAME_INSB, CDISASM_X86_NAME_INSW,
        CDISASM_X86_NAME_INSD
    },
    {
        CDISASM_X86_NAME_OUTSB, CDISASM_X86_NAME_OUTSW,
        CDISASM_X86_NAME_OUTSD
    }
};

static uint64_t mnemonic_required_caps(cdisasm_x86_name_id name_id)
{
    if ((name_id >= CDISASM_X86_NAME_CMOVA && name_id <= CDISASM_X86_NAME_CMOVS)
        || name_id == CDISASM_X86_NAME_RDPMC
        || name_id == CDISASM_X86_NAME_UD2) {
        return X86_CAP_P6;
    }
    if (name_id >= CDISASM_X86_NAME_SETA && name_id <= CDISASM_X86_NAME_SETS) {
        return X86_CAP_80386;
    }

    switch (name_id) {
        case CDISASM_X86_NAME_ENTER:
        case CDISASM_X86_NAME_INSB:
        case CDISASM_X86_NAME_INSD:
        case CDISASM_X86_NAME_INSW:
        case CDISASM_X86_NAME_LEAVE:
        case CDISASM_X86_NAME_OUTSB:
        case CDISASM_X86_NAME_OUTSD:
        case CDISASM_X86_NAME_OUTSW:
        case CDISASM_X86_NAME_POPA:
        case CDISASM_X86_NAME_POPAD:
        case CDISASM_X86_NAME_PUSHA:
        case CDISASM_X86_NAME_PUSHAD:
        case CDISASM_X86_NAME_BOUND:
            return X86_CAP_80186;

        case CDISASM_X86_NAME_ARPL:
        case CDISASM_X86_NAME_CLTS:
        case CDISASM_X86_NAME_LAR:
        case CDISASM_X86_NAME_LGDT:
        case CDISASM_X86_NAME_LIDT:
        case CDISASM_X86_NAME_LLDT:
        case CDISASM_X86_NAME_LMSW:
        case CDISASM_X86_NAME_LSL:
        case CDISASM_X86_NAME_LTR:
        case CDISASM_X86_NAME_SGDT:
        case CDISASM_X86_NAME_SIDT:
        case CDISASM_X86_NAME_SLDT:
        case CDISASM_X86_NAME_SMSW:
        case CDISASM_X86_NAME_STR:
        case CDISASM_X86_NAME_VERR:
        case CDISASM_X86_NAME_VERW:
            return X86_CAP_80286;

        case CDISASM_X86_NAME_BSF:
        case CDISASM_X86_NAME_BSR:
        case CDISASM_X86_NAME_BT:
        case CDISASM_X86_NAME_BTC:
        case CDISASM_X86_NAME_BTR:
        case CDISASM_X86_NAME_BTS:
        case CDISASM_X86_NAME_INT1:
        case CDISASM_X86_NAME_LFS:
        case CDISASM_X86_NAME_LGS:
        case CDISASM_X86_NAME_LSS:
        case CDISASM_X86_NAME_MOVSX:
        case CDISASM_X86_NAME_MOVZX:
        case CDISASM_X86_NAME_SHLD:
        case CDISASM_X86_NAME_SHRD:
            return X86_CAP_80386;

        case CDISASM_X86_NAME_BSWAP:
        case CDISASM_X86_NAME_CMPXCHG:
        case CDISASM_X86_NAME_INVD:
        case CDISASM_X86_NAME_INVLPG:
        case CDISASM_X86_NAME_WBINVD:
        case CDISASM_X86_NAME_XADD:
            return X86_CAP_80486;

        case CDISASM_X86_NAME_CPUID:
            return X86_CAP_CPUID;
        case CDISASM_X86_NAME_RDMSR:
        case CDISASM_X86_NAME_RDTSC:
        case CDISASM_X86_NAME_WRMSR:
        case CDISASM_X86_NAME_CMPXCHG8B:
            return X86_CAP_PENTIUM;

        case CDISASM_X86_NAME_CMPXCHG16B:
            return X86_CAP_CMPXCHG16B;
        case CDISASM_X86_NAME_FXSAVE:
        case CDISASM_X86_NAME_FXSAVE64:
        case CDISASM_X86_NAME_FXRSTOR:
        case CDISASM_X86_NAME_FXRSTOR64:
            return X86_CAP_FXSR;
        case CDISASM_X86_NAME_LFENCE:
        case CDISASM_X86_NAME_MFENCE:
            return X86_CAP_SSE2;
        case CDISASM_X86_NAME_MONITOR:
        case CDISASM_X86_NAME_MWAIT:
            return X86_CAP_MONITOR;
        case CDISASM_X86_NAME_RDTSCP:
            return X86_CAP_RDTSCP;

        case CDISASM_X86_NAME_EMMS:
            return X86_CAP_MMX;
        case CDISASM_X86_NAME_UD0:
            return X86_CAP_UD0;
        case CDISASM_X86_NAME_UD1:
            return X86_CAP_UD1;
        case CDISASM_X86_NAME_FEMMS:
        case CDISASM_X86_NAME_PAVGUSB:
        case CDISASM_X86_NAME_PF2ID:
        case CDISASM_X86_NAME_PFACC:
        case CDISASM_X86_NAME_PFADD:
        case CDISASM_X86_NAME_PFCMPEQ:
        case CDISASM_X86_NAME_PFCMPGE:
        case CDISASM_X86_NAME_PFCMPGT:
        case CDISASM_X86_NAME_PFMAX:
        case CDISASM_X86_NAME_PFMIN:
        case CDISASM_X86_NAME_PFMUL:
        case CDISASM_X86_NAME_PFRCP:
        case CDISASM_X86_NAME_PFRCPIT1:
        case CDISASM_X86_NAME_PFRCPIT2:
        case CDISASM_X86_NAME_PFRSQIT1:
        case CDISASM_X86_NAME_PFRSQRT:
        case CDISASM_X86_NAME_PFSUB:
        case CDISASM_X86_NAME_PFSUBR:
        case CDISASM_X86_NAME_PI2FD:
        case CDISASM_X86_NAME_PMULHRW:
            return X86_CAP_3DNOW;
        case CDISASM_X86_NAME_PF2IW:
        case CDISASM_X86_NAME_PI2FW:
        case CDISASM_X86_NAME_PFNACC:
        case CDISASM_X86_NAME_PFPNACC:
        case CDISASM_X86_NAME_PSWAPD:
            return X86_CAP_3DNOW_EXT;
        case CDISASM_X86_NAME_PREFETCH:
            return X86_CAP_PREFETCH;
        case CDISASM_X86_NAME_PREFETCHW:
            return X86_CAP_PREFETCHW;
        case CDISASM_X86_NAME_SYSENTER:
        case CDISASM_X86_NAME_SYSEXIT:
            return X86_CAP_SEP;
        case CDISASM_X86_NAME_PAUSE:
            return X86_CAP_PAUSE;
        case CDISASM_X86_NAME_SYSCALL:
        case CDISASM_X86_NAME_SYSRET:
        case CDISASM_X86_NAME_UDB:
            return X86_CAP_AMD64;
        case CDISASM_X86_NAME_GETSEC:
            return X86_CAP_SMX;
        case CDISASM_X86_NAME_LZCNT:
        case CDISASM_X86_NAME_POPCNT:
            return name_id == CDISASM_X86_NAME_LZCNT ? X86_CAP_LZCNT : X86_CAP_POPCNT;
        case CDISASM_X86_NAME_TZCNT:
            return X86_CAP_BMI1;
        case CDISASM_X86_NAME_ENDBR32:
        case CDISASM_X86_NAME_ENDBR64:
            return X86_CAP_CET_IBT;
        case CDISASM_X86_NAME_VMCALL:
        case CDISASM_X86_NAME_VMCLEAR:
        case CDISASM_X86_NAME_VMLAUNCH:
        case CDISASM_X86_NAME_VMPTRLD:
        case CDISASM_X86_NAME_VMPTRST:
        case CDISASM_X86_NAME_VMREAD:
        case CDISASM_X86_NAME_VMRESUME:
        case CDISASM_X86_NAME_VMWRITE:
        case CDISASM_X86_NAME_VMXOFF:
        case CDISASM_X86_NAME_VMXON:
            return X86_CAP_VMX;
        case CDISASM_X86_NAME_INVEPT:
            return X86_CAP_VMX | X86_CAP_INVEPT;
        case CDISASM_X86_NAME_INVVPID:
            return X86_CAP_VMX | X86_CAP_INVVPID;
        case CDISASM_X86_NAME_VMFUNC:
            return X86_CAP_VMX | X86_CAP_VMFUNC;
        case CDISASM_X86_NAME_CLGI:
        case CDISASM_X86_NAME_INVLPGA:
        case CDISASM_X86_NAME_SKINIT:
        case CDISASM_X86_NAME_STGI:
        case CDISASM_X86_NAME_VMLOAD:
        case CDISASM_X86_NAME_VMMCALL:
        case CDISASM_X86_NAME_VMRUN:
        case CDISASM_X86_NAME_VMSAVE:
            return X86_CAP_SVM;
        case CDISASM_X86_NAME_VMGEXIT:
            return X86_CAP_SVM | X86_CAP_SEV_ES;
        case CDISASM_X86_NAME_VZEROALL:
        case CDISASM_X86_NAME_VZEROUPPER:
            return X86_CAP_AVX;
        default:
            return 0;
    }
}

static uint64_t cpu_capabilities(cdisasm_cpu_id cpu_id)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
            return X86_CAP_ALL;
        case CDISASM_CPU_8086:
            return X86_CAPS_86;
        case CDISASM_CPU_80186:
            return X86_CAPS_186;
        case CDISASM_CPU_80286:
            return X86_CAPS_286;
        case CDISASM_CPU_80386:
            return X86_CAPS_386;
        case CDISASM_CPU_80486:
            return X86_CAPS_486;
        case CDISASM_CPU_80486_CPUID:
            return X86_CAPS_486_CPUID;
        case CDISASM_CPU_PENTIUM:
            return X86_CAPS_PENTIUM;
        case CDISASM_CPU_PENTIUM_PRO:
            return X86_CAPS_PENTIUM_PRO;
        case CDISASM_CPU_PENTIUM_MMX:
            return X86_CAPS_PENTIUM_MMX;
        case CDISASM_CPU_AMD_K6_2:
            return X86_CAPS_K6_2;
        case CDISASM_CPU_PENTIUM_II:
            return X86_CAPS_PENTIUM_II;
        case CDISASM_CPU_PENTIUM_III:
            return X86_CAPS_PENTIUM_III;
        case CDISASM_CPU_PENTIUM_4:
            return X86_CAPS_PENTIUM_4;
        case CDISASM_CPU_ATHLON_64:
            return X86_CAPS_ATHLON_64;
        case CDISASM_CPU_AMD_V:
            return X86_CAPS_AMD_V;
        case CDISASM_CPU_PRESCOTT:
            return X86_CAPS_PRESCOTT;
        case CDISASM_CPU_INTEL_VT_X:
            return X86_CAPS_INTEL_VTX;
        case CDISASM_CPU_CORE_2:
            return X86_CAPS_CORE_2;
        case CDISASM_CPU_PENRYN:
            return X86_CAPS_PENRYN;
        case CDISASM_CPU_AMD_BARCELONA:
            return X86_CAPS_BARCELONA;
        case CDISASM_CPU_AMD_BULLDOZER:
            return X86_CAPS_BULLDOZER;
        case CDISASM_CPU_NEHALEM:
        case CDISASM_CPU_WESTMERE:
            return X86_CAPS_NEHALEM;
        case CDISASM_CPU_SANDY_BRIDGE:
        case CDISASM_CPU_IVY_BRIDGE:
            return X86_CAPS_SANDY_BRIDGE;
        case CDISASM_CPU_HASWELL:
            return X86_CAPS_HASWELL;
        case CDISASM_CPU_BROADWELL:
            return X86_CAPS_BROADWELL;
        case CDISASM_CPU_SKYLAKE:
            return X86_CAPS_BROADWELL | X86_CAP_CLFLUSHOPT;
        case CDISASM_CPU_SKYLAKE_SP:
            return X86_CAPS_BROADWELL | X86_CAP_CLFLUSHOPT | X86_CAP_CLWB;
        case CDISASM_CPU_ICE_LAKE:
            return (X86_CAPS_BROADWELL & ~X86_CAP_HLE)
                | X86_CAP_CLFLUSHOPT | X86_CAP_RDPID;
        case CDISASM_CPU_GOLDMONT:
            return (X86_CAPS_BROADWELL
                    & ~(X86_CAP_HLE | X86_CAP_AVX | X86_CAP_AVX2))
                | X86_CAP_CLFLUSHOPT;
        case CDISASM_CPU_AMD_ZEN:
            return X86_CAPS_ZEN | X86_CAP_CLFLUSHOPT;
        case CDISASM_CPU_TIGER_LAKE:
            return (X86_CAPS_BROADWELL & ~X86_CAP_HLE)
                | X86_CAP_CET_IBT | X86_CAP_CLFLUSHOPT | X86_CAP_CLWB
                | X86_CAP_RDPID | X86_CAP_MOVDIRI | X86_CAP_MOVDIR64B
                | X86_CAP_WBNOINVD;
        case CDISASM_CPU_ALDER_LAKE:
        case CDISASM_CPU_ARROW_LAKE:
            return (X86_CAPS_BROADWELL & ~X86_CAP_HLE)
                | X86_CAP_CET_IBT | X86_CAP_CLFLUSHOPT | X86_CAP_CLWB
                | X86_CAP_RDPID | X86_CAP_SERIALIZE | X86_CAP_MOVDIRI
                | X86_CAP_MOVDIR64B | X86_CAP_WBNOINVD;
        case CDISASM_CPU_AVX10:
            return (X86_CAPS_BROADWELL & ~X86_CAP_HLE)
                | X86_CAP_CET_IBT;
        case CDISASM_CPU_APX:
            return (X86_CAPS_BROADWELL & ~X86_CAP_HLE)
                | X86_CAP_CET_IBT | X86_CAP_RDPID | X86_CAP_SERIALIZE
                | X86_CAP_MOVDIRI | X86_CAP_MOVDIR64B | X86_CAP_WBNOINVD;
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return X86_CAPS_BROADWELL | X86_CAP_CET_IBT
                | X86_CAP_CLFLUSHOPT | X86_CAP_CLWB | X86_CAP_RDPID
                | X86_CAP_SERIALIZE | X86_CAP_MOVDIRI | X86_CAP_MOVDIR64B
                | X86_CAP_WBNOINVD;
        case CDISASM_CPU_KNIGHTS_MILL:
            /* XED models KNM as Ivy Bridge plus AVX2/FMA/BMI/ADX and the
             * Knights-specific AVX-512 subsets.  Optional families are
             * recorded independently in cpu_extra_capabilities(). */
            return X86_CAPS_SANDY_BRIDGE | X86_CAP_AVX2
                | X86_CAP_LZCNT | X86_CAP_BMI1 | X86_CAP_PREFETCHW
                | X86_CAP_VMFUNC;
        case CDISASM_CPU_AMD_ZEN_4:
            return X86_CAPS_ZEN | X86_CAP_SEV_ES | X86_CAP_CET_IBT
                | X86_CAP_CLFLUSHOPT | X86_CAP_CLWB | X86_CAP_RDPID
                | X86_CAP_WBNOINVD;
        case CDISASM_CPU_CELERON_G3900:
        case CDISASM_CPU_CELERON_G5900:
            return X86_CAPS_LOWEND_SSE42 | X86_CAP_CLFLUSHOPT;
        case CDISASM_CPU_CELERON_G1840:
            return X86_CAPS_LOWEND_SSE42;
        case CDISASM_CPU_CELERON_N3350:
            return X86_CAPS_LOWEND_ATOM_SSE42 | X86_CAP_CLFLUSHOPT;
        case CDISASM_CPU_CELERON_N4020:
            return X86_CAPS_LOWEND_ATOM_SSE42
                | X86_CAP_CLFLUSHOPT | X86_CAP_RDPID;
        case CDISASM_CPU_PENTIUM_SILVER_N6000:
            return X86_CAPS_LOWEND_ATOM_SSE42
                | X86_CAP_CLFLUSHOPT | X86_CAP_CLWB | X86_CAP_RDPID;
        case CDISASM_CPU_8086_8087:
            return X86_CAPS_86 | X86_CAP_X87;
        case CDISASM_CPU_80186_80187:
            /* Intel's 80C187 implements the full 80387DX instruction set. */
            return X86_CAPS_186 | X86_CAP_X87
                | X86_CAP_X87_287 | X86_CAP_X87_387;
        case CDISASM_CPU_80286_80287:
            return X86_CAPS_286 | X86_CAP_X87 | X86_CAP_X87_287;
        case CDISASM_CPU_80386_80387:
            return X86_CAPS_386 | X86_CAP_X87
                | X86_CAP_X87_287 | X86_CAP_X87_387;
        default:
            return 0;
    }
}

#if USE_EXTRA_OPCODES
static uint64_t cpu_extra_capabilities(cdisasm_cpu_id cpu_id);
#endif

int cdisasm_x86_cpu_admits_generated_core(
    cdisasm_cpu_id cpu_id,
    cdisasm_x86_name_id name_id,
    cdisasm_x86_group_id group_id)
{
    uint64_t required = mnemonic_required_caps(name_id);

    switch (group_id) {
        case CDISASM_X86_GROUP_I186:
            required |= X86_CAP_80186;
            break;
        case CDISASM_X86_GROUP_I286:
            required |= X86_CAP_80286;
            break;
        case CDISASM_X86_GROUP_I386:
            required |= X86_CAP_80386;
            break;
        case CDISASM_X86_GROUP_I486:
            required |= X86_CAP_80486;
            break;
        case CDISASM_X86_GROUP_CMOV:
            required |= X86_CAP_P6;
            break;
        case CDISASM_X86_GROUP_CMPXCHG16B:
            required |= X86_CAP_CMPXCHG16B;
            break;
        default:
            break;
    }
    if ((required & ~cpu_capabilities(cpu_id)) != 0) {
        return 0;
    }
#if USE_EXTRA_OPCODES
    if (group_id == CDISASM_X86_GROUP_MOVBE
        && cpu_id != CDISASM_CPU_X86
        && (cpu_extra_capabilities(cpu_id)
            & X86_EXTRA_CAP(CDISASM_X86_GROUP_MOVBE)) == 0) {
        return 0;
    }
#else
    (void)group_id;
#endif
    return 1;
}

#if USE_EXTRA_OPCODES
static uint64_t cpu_extra_capabilities(cdisasm_cpu_id cpu_id)
{
    const uint64_t aesni = X86_EXTRA_CAP(CDISASM_X86_GROUP_AESNI);
    const uint64_t pclmul = X86_EXTRA_CAP(CDISASM_X86_GROUP_PCLMULQDQ);
    const uint64_t aes = aesni | pclmul;
    const uint64_t rdrand = X86_EXTRA_CAP(CDISASM_X86_GROUP_RDRAND);
    const uint64_t rdseed = X86_EXTRA_CAP(CDISASM_X86_GROUP_RDSEED);
    const uint64_t entropy = rdrand | rdseed;
    const uint64_t rtm = X86_EXTRA_CAP(CDISASM_X86_GROUP_RTM);
    const uint64_t bmi = X86_EXTRA_CAP(CDISASM_X86_GROUP_BMI1)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_BMI2);
    const uint64_t avx512_core = X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512F)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512CD)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512DQ)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512BW)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VL);
    const uint64_t avx512_late = avx512_core
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512IFMA)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VBMI)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VBMI2)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VPOPCNTDQ)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512BITALG)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VNNI);
    const uint64_t avx512_knm =
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512F)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512CD)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512ER)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512PF)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VPOPCNTDQ)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512_4VNNIW)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512_4FMAPS);
    const uint64_t avx_common = X86_EXTRA_CAP(CDISASM_X86_GROUP_F16C)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_FMA3) | bmi;
    const uint64_t avx_vnni =
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX_VNNI);
    const uint64_t vector_crypto = X86_EXTRA_CAP(CDISASM_X86_GROUP_VAES)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_VPCLMULQDQ);
    const uint64_t gfni = X86_EXTRA_CAP(CDISASM_X86_GROUP_GFNI);
    const uint64_t vp2intersect =
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VP2INTERSECT);
    const uint64_t cet_ss = X86_EXTRA_CAP(CDISASM_X86_GROUP_CET_SS);
    const uint64_t waitpkg = X86_EXTRA_CAP(CDISASM_X86_GROUP_WAITPKG);
    const uint64_t arrow_crypto =
        X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA512)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_SM3)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_SM4);
    const uint64_t xsave = X86_EXTRA_CAP(CDISASM_X86_GROUP_XSAVE);
    const uint64_t xsave_opt = xsave
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_XSAVEOPT);
    const uint64_t xsave_compacted = xsave_opt
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_XSAVEC)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_XSAVES);
    const uint64_t fsgsbase =
        X86_EXTRA_CAP(CDISASM_X86_GROUP_FSGSBASE);
    const uint64_t haswell_system = fsgsbase
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_INVPCID)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_MOVBE);
    const uint64_t adx = X86_EXTRA_CAP(CDISASM_X86_GROUP_ADX);
    const uint64_t skylake_security =
        X86_EXTRA_CAP(CDISASM_X86_GROUP_SGX)
        | X86_EXTRA_CAP(CDISASM_X86_GROUP_MPX);
    const uint64_t sgx = X86_EXTRA_CAP(CDISASM_X86_GROUP_SGX);

    switch (cpu_id) {
        case CDISASM_CPU_X86:
            return X86_EXTRA_CAP_ALL;
        case CDISASM_CPU_NEHALEM:
            return xsave;
        case CDISASM_CPU_WESTMERE:
            return aes | xsave;
        case CDISASM_CPU_SANDY_BRIDGE:
            return aes | xsave_opt;
        case CDISASM_CPU_IVY_BRIDGE:
            return aes | rdrand
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_F16C)
                | xsave_opt | fsgsbase;
        case CDISASM_CPU_HASWELL:
            return aes | avx_common | rdrand | rtm
                | xsave_opt | haswell_system;
        case CDISASM_CPU_BROADWELL:
            return aes | avx_common | entropy | rtm
                | xsave_opt | haswell_system | adx;
        case CDISASM_CPU_SKYLAKE:
            return aes | avx_common | entropy | rtm
                | xsave_compacted | haswell_system | adx
                | skylake_security;
        case CDISASM_CPU_SKYLAKE_SP:
            return aes | avx_common | avx512_core | entropy | rtm
                | xsave_compacted | haswell_system | adx
                | skylake_security;
        case CDISASM_CPU_ICE_LAKE:
            return aes | avx_common | avx512_late | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA) | entropy
                | xsave_compacted | haswell_system | adx | sgx;
        case CDISASM_CPU_TIGER_LAKE:
            return aes | avx_common | avx512_late | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA) | entropy | cet_ss
                | xsave_compacted | haswell_system | adx | sgx
                | vp2intersect;
        case CDISASM_CPU_ALDER_LAKE:
            return aes | avx_common | avx_vnni | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA) | entropy | cet_ss
                | waitpkg | xsave_compacted | haswell_system | adx;
        case CDISASM_CPU_ARROW_LAKE:
            return aes | avx_common | avx_vnni | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA) | arrow_crypto
                | entropy | cet_ss | waitpkg | xsave_compacted
                | haswell_system | adx;
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
            return aes | avx_common | avx_vnni | avx512_late
                | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512FP16)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_TILE)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_INT8)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_BF16)
                | entropy | rtm | cet_ss | waitpkg | xsave_compacted
                | haswell_system | adx | sgx;
        case CDISASM_CPU_GRANITE_RAPIDS:
            return aes | avx_common | avx_vnni | avx512_late
                | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512FP16)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_TILE)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_INT8)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_BF16)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_FP16)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1)
                | entropy | rtm | cet_ss | waitpkg | xsave_compacted
                | haswell_system | adx;
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return aes | avx_common | avx_vnni | avx512_late
                | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512FP16)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA512)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SM3)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SM4)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_TILE)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_INT8)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_BF16)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_FP16)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_2)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_APX_F)
                | entropy | rtm | cet_ss | waitpkg | xsave_compacted
                | haswell_system | adx;
        case CDISASM_CPU_KNIGHTS_MILL:
            return aes | avx_common | avx512_knm | entropy
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_ADX)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_MOVBE);
        case CDISASM_CPU_AMD_BULLDOZER:
            return aes | X86_EXTRA_CAP(CDISASM_X86_GROUP_XOP)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_FMA4) | xsave;
        case CDISASM_CPU_AMD_ZEN:
            return aes | avx_common | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA)
                | entropy | xsave_compacted | fsgsbase | adx
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_MOVBE);
        case CDISASM_CPU_AMD_ZEN_4:
            return aes | avx_common | avx512_late | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA) | entropy | cet_ss
                | xsave_compacted | fsgsbase | adx
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_MOVBE);
        case CDISASM_CPU_GOLDMONT:
            return aes | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA) | entropy
                | xsave_compacted | fsgsbase
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_MOVBE)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_MPX);
        case CDISASM_CPU_CELERON_G1840:
            return rdrand | xsave_opt | haswell_system;
        case CDISASM_CPU_CELERON_G3900:
        case CDISASM_CPU_CELERON_G5900:
            return aes | entropy | xsave_compacted | haswell_system | adx;
        case CDISASM_CPU_CELERON_N3350:
        case CDISASM_CPU_CELERON_N4020:
            return aes | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA) | entropy
                | xsave_compacted | fsgsbase
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_MOVBE);
        case CDISASM_CPU_PENTIUM_SILVER_N6000:
            return aes | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA) | gfni
                | entropy
                | waitpkg | xsave_compacted | fsgsbase
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_MOVBE);
        case CDISASM_CPU_AVX10:
            return aes | avx_common | avx_vnni | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_2)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VL)
                | entropy | cet_ss | xsave_compacted | haswell_system | adx;
        case CDISASM_CPU_APX:
            return aes | avx_common | avx_vnni | vector_crypto | gfni
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_2)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VL)
                | X86_EXTRA_CAP(CDISASM_X86_GROUP_APX_F)
                | entropy | cet_ss | xsave_compacted | haswell_system | adx;
        default:
            return 0;
    }
}

static uint64_t cpu_extra_capabilities_high(cdisasm_cpu_id cpu_id)
{
    const uint64_t complex =
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_COMPLEX);
    const uint64_t avx_vnni_int8 =
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AVX_VNNI_INT8);
    const uint64_t avx_vnni_int16 =
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AVX_VNNI_INT16);
    const uint64_t pku =
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_PKU);
    const uint64_t avx10_movrs =
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AVX10_MOVRS_128)
        | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AVX10_MOVRS_256)
        | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AVX10_MOVRS_512);
    const uint64_t spr_system =
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_UINTR)
        | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_TSX_LDTRK)
        | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_ENQCMD);

    switch (cpu_id) {
        case CDISASM_CPU_X86:
            return X86_EXTRA_CAP_ALL;
        case CDISASM_CPU_SKYLAKE:
        case CDISASM_CPU_SKYLAKE_SP:
        case CDISASM_CPU_ICE_LAKE:
        case CDISASM_CPU_TIGER_LAKE:
        case CDISASM_CPU_ALDER_LAKE:
            return pku;
        case CDISASM_CPU_AVX10:
            return pku | avx10_movrs;
        case CDISASM_CPU_APX:
            return pku | avx10_movrs
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_APX_F_ADX)
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_APX_F_ADX_N3)
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_APX_F_BMI1)
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_APX_F_BMI1_N3)
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_APX_F_BMI2)
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_APX_F_BMI2_N3)
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_APX_F_N3);
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
            return pku | spr_system;
        case CDISASM_CPU_ARROW_LAKE:
            return avx_vnni_int8 | avx_vnni_int16 | pku
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_UINTR);
        case CDISASM_CPU_GRANITE_RAPIDS:
            return complex | pku | spr_system;
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return complex
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_FP8)
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_MOVRS)
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_AVX512)
                | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_APX_F_N3)
                | avx_vnni_int8 | avx_vnni_int16 | pku | spr_system
                | avx10_movrs;
        default:
            return UINT64_C(0);
    }
}

cdisasm_x86_decode_option cdisasm_x86_cpu_decode_flag_mask_core(
    cdisasm_cpu_id cpu_id,
    cdisasm_mode mode)
{
    const uint64_t caps = cpu_capabilities(cpu_id);
    const uint64_t extra_caps = cpu_extra_capabilities(cpu_id);
    const uint64_t extra_caps_high = cpu_extra_capabilities_high(cpu_id);
    cdisasm_x86_decode_option flags = CDISASM_X86_DECODE_FLAG_SYSTEM
        | CDISASM_X86_DECODE_FLAG_UNDOCUMENTED;

    if (cpu_id == CDISASM_CPU_X86) {
        cdisasm_x86_decode_option unrestricted =
            CDISASM_X86_DECODE_FLAG_KNOWN_MASK
            & ~CDISASM_X86_DECODE_FLAG_GFNI;

        if (mode != CDISASM_MODE_64) {
            unrestricted &=
                ~(CDISASM_X86_DECODE_FLAG_AMX
                    | CDISASM_X86_DECODE_FLAG_AMX_TILE
                    | CDISASM_X86_DECODE_FLAG_AMX_INT8
                    | CDISASM_X86_DECODE_FLAG_AMX_BF16
                    | CDISASM_X86_DECODE_FLAG_AMX_FP16
                    | CDISASM_X86_DECODE_FLAG_AMX_COMPLEX
                    | CDISASM_X86_DECODE_FLAG_AMX_FP8
                    | CDISASM_X86_DECODE_FLAG_AMX_MOVRS
                    | CDISASM_X86_DECODE_FLAG_AMX_AVX512
                    | CDISASM_X86_DECODE_FLAG_APX);
        }
        return unrestricted;
    }

#define ADD_CORE_FLAG(capability_mask_, flag_) \
    do { \
        if ((caps & (capability_mask_)) != 0) { \
            flags |= (flag_); \
        } \
    } while (0)
#define ADD_EXTRA_FLAG(capability_mask_, flag_) \
    do { \
        if ((extra_caps & (capability_mask_)) != 0) { \
            flags |= (flag_); \
        } \
    } while (0)
#define ADD_EXTRA_FLAG_HIGH(capability_mask_, flag_) \
    do { \
        if ((extra_caps_high & (capability_mask_)) != 0) { \
            flags |= (flag_); \
        } \
    } while (0)

    ADD_CORE_FLAG(X86_CAP_X87, CDISASM_X86_DECODE_FLAG_FPU);
    ADD_CORE_FLAG(X86_CAP_MMX, CDISASM_X86_DECODE_FLAG_MMX);
    ADD_CORE_FLAG(
        X86_CAP_3DNOW | X86_CAP_3DNOW_EXT,
        CDISASM_X86_DECODE_FLAG_3DNOW);
    ADD_CORE_FLAG(X86_CAP_SSE, CDISASM_X86_DECODE_FLAG_SSE);
    ADD_CORE_FLAG(X86_CAP_SSE2, CDISASM_X86_DECODE_FLAG_SSE2);
    ADD_CORE_FLAG(X86_CAP_SSE3, CDISASM_X86_DECODE_FLAG_SSE3);
    ADD_CORE_FLAG(X86_CAP_SSSE3, CDISASM_X86_DECODE_FLAG_SSSE3);
    ADD_CORE_FLAG(
        X86_CAP_SSE41 | X86_CAP_SSE4A | X86_CAP_SSE42,
        CDISASM_X86_DECODE_FLAG_SSE4);
    ADD_CORE_FLAG(X86_CAP_SSE41, CDISASM_X86_DECODE_FLAG_SSE41);
    ADD_CORE_FLAG(X86_CAP_SSE42, CDISASM_X86_DECODE_FLAG_SSE42);
    ADD_CORE_FLAG(X86_CAP_SSE4A, CDISASM_X86_DECODE_FLAG_SSE4A);
    ADD_CORE_FLAG(X86_CAP_AVX, CDISASM_X86_DECODE_FLAG_AVX);
    ADD_CORE_FLAG(X86_CAP_AVX2, CDISASM_X86_DECODE_FLAG_AVX2);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX_VNNI),
        CDISASM_X86_DECODE_FLAG_AVX_VNNI);
    ADD_EXTRA_FLAG_HIGH(
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AVX_VNNI_INT8),
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8);
    ADD_EXTRA_FLAG_HIGH(
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AVX_VNNI_INT16),
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16);
    ADD_CORE_FLAG(
        X86_CAP_LZCNT | X86_CAP_POPCNT | X86_CAP_BMI1,
        CDISASM_X86_DECODE_FLAG_BITMANIP);
    ADD_CORE_FLAG(X86_CAP_BMI1, CDISASM_X86_DECODE_FLAG_BMI1);
    ADD_CORE_FLAG(X86_CAP_SMX, CDISASM_X86_DECODE_FLAG_SMX);
    ADD_CORE_FLAG(X86_CAP_VMX, CDISASM_X86_DECODE_FLAG_VMX);
    ADD_CORE_FLAG(
        X86_CAP_SVM | X86_CAP_SEV_ES, CDISASM_X86_DECODE_FLAG_SVM);
    ADD_CORE_FLAG(X86_CAP_CET_IBT, CDISASM_X86_DECODE_FLAG_CET);
    ADD_CORE_FLAG(X86_CAP_FXSR, CDISASM_X86_DECODE_FLAG_STATE);
    ADD_CORE_FLAG(
        X86_CAP_MONITOR | X86_CAP_RDTSCP,
        CDISASM_X86_DECODE_FLAG_SYSTEM);
    ADD_CORE_FLAG(X86_CAP_HLE, CDISASM_X86_DECODE_FLAG_TRANSACTIONAL);
    ADD_CORE_FLAG(
        X86_CAP_PREFETCH | X86_CAP_PREFETCHW | X86_CAP_PAUSE | X86_CAP_SSE
            | X86_CAP_CLFLUSH | X86_CAP_CLFLUSHOPT | X86_CAP_CLWB,
        CDISASM_X86_DECODE_FLAG_MEMORY_HINTS);

    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_F16C),
        CDISASM_X86_DECODE_FLAG_F16C);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_FMA3),
        CDISASM_X86_DECODE_FLAG_FMA3);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_XOP),
        CDISASM_X86_DECODE_FLAG_XOP);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_FMA4),
        CDISASM_X86_DECODE_FLAG_FMA4);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AESNI)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_VAES),
        CDISASM_X86_DECODE_FLAG_AES);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_VAES),
        CDISASM_X86_DECODE_FLAG_VAES);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_PCLMULQDQ)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_VPCLMULQDQ),
        CDISASM_X86_DECODE_FLAG_PCLMUL);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_VPCLMULQDQ),
        CDISASM_X86_DECODE_FLAG_VPCLMULQDQ);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA512),
        CDISASM_X86_DECODE_FLAG_SHA);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_SHA512),
        CDISASM_X86_DECODE_FLAG_SHA512);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_SM3),
        CDISASM_X86_DECODE_FLAG_SM3);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_SM4),
        CDISASM_X86_DECODE_FLAG_SM4);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_GFNI),
        CDISASM_X86_DECODE_FLAG_GFNI);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_RDRAND)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_RDSEED)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_SGX)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_MPX),
        CDISASM_X86_DECODE_FLAG_SECURITY);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_RTM),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL);
    ADD_EXTRA_FLAG_HIGH(
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_TSX_LDTRK),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_XSAVE)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_XSAVEOPT)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_XSAVEC)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_XSAVES),
        CDISASM_X86_DECODE_FLAG_STATE);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_FSGSBASE)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_INVPCID),
        CDISASM_X86_DECODE_FLAG_SYSTEM);
    ADD_EXTRA_FLAG_HIGH(
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_PKU),
        CDISASM_X86_DECODE_FLAG_SECURITY);
    ADD_EXTRA_FLAG_HIGH(
        X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_UINTR)
            | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_ENQCMD),
        CDISASM_X86_DECODE_FLAG_SYSTEM);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_TBM)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_BMI1)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_BMI2)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_ADX),
        CDISASM_X86_DECODE_FLAG_BITMANIP);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_BMI1),
        CDISASM_X86_DECODE_FLAG_BMI1);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_BMI2),
        CDISASM_X86_DECODE_FLAG_BMI2);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512F),
        CDISASM_X86_DECODE_FLAG_AVX512);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512IFMA),
        CDISASM_X86_DECODE_FLAG_AVX512_IFMA);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VBMI)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VNNI)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512DQ),
        CDISASM_X86_DECODE_FLAG_AVX512_DQ);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512BW),
        CDISASM_X86_DECODE_FLAG_AVX512_BW);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VBMI2)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI2);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VPOPCNTDQ)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1),
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512BITALG)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1),
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512CD)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1),
        CDISASM_X86_DECODE_FLAG_AVX512_CD);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512F)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1),
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_1)
            | X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX10_2),
        CDISASM_X86_DECODE_FLAG_AVX10);
    ADD_EXTRA_FLAG(
        X86_EXTRA_CAP(CDISASM_X86_GROUP_CET_SS),
        CDISASM_X86_DECODE_FLAG_CET);
    if (mode == CDISASM_MODE_64) {
        ADD_EXTRA_FLAG(
            X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_TILE),
            CDISASM_X86_DECODE_FLAG_AMX);
        ADD_EXTRA_FLAG(
            X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_TILE),
            CDISASM_X86_DECODE_FLAG_AMX_TILE);
        ADD_EXTRA_FLAG(
            X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_INT8),
            CDISASM_X86_DECODE_FLAG_AMX_INT8);
        ADD_EXTRA_FLAG(
            X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_BF16),
            CDISASM_X86_DECODE_FLAG_AMX_BF16);
        ADD_EXTRA_FLAG(
            X86_EXTRA_CAP(CDISASM_X86_GROUP_AMX_FP16),
            CDISASM_X86_DECODE_FLAG_AMX_FP16);
        ADD_EXTRA_FLAG_HIGH(
            X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_COMPLEX),
            CDISASM_X86_DECODE_FLAG_AMX_COMPLEX);
        ADD_EXTRA_FLAG_HIGH(
            X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_FP8),
            CDISASM_X86_DECODE_FLAG_AMX_FP8);
        ADD_EXTRA_FLAG_HIGH(
            X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_MOVRS),
            CDISASM_X86_DECODE_FLAG_AMX_MOVRS);
        ADD_EXTRA_FLAG_HIGH(
            X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_AVX512),
            CDISASM_X86_DECODE_FLAG_AMX_AVX512);
        ADD_EXTRA_FLAG(
            X86_EXTRA_CAP(CDISASM_X86_GROUP_APX_F),
            CDISASM_X86_DECODE_FLAG_APX);
        if ((extra_caps_high
                & (X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_COMPLEX)
                    | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_FP8)
                    | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_MOVRS)
                    | X86_EXTRA_CAP_HIGH(CDISASM_X86_GROUP_AMX_AVX512)))
            != 0) {
            flags |= CDISASM_X86_DECODE_FLAG_AMX;
        }
    }

#undef ADD_EXTRA_FLAG
#undef ADD_EXTRA_FLAG_HIGH
#undef ADD_CORE_FLAG
    return flags & CDISASM_X86_DECODE_FLAG_KNOWN_MASK;
}

static void decoder_require_extra(
    x86_decoder *decoder,
    cdisasm_x86_group_id group_id)
{
    if (group_id < X86_EXTRA_GROUP_HIGH_BASE) {
        const uint64_t bit = X86_EXTRA_CAP(group_id);

        decoder->required_extra_caps |= bit;
        decoder->used_extra_groups |= bit;
    } else {
        const uint64_t bit = X86_EXTRA_CAP_HIGH(group_id);

        decoder->required_extra_caps_high |= bit;
        decoder->used_extra_groups_high |= bit;
    }
}

static int decoder_has_extra(
    const x86_decoder *decoder,
    cdisasm_x86_group_id group_id)
{
    return group_id < X86_EXTRA_GROUP_HIGH_BASE
        ? (decoder->cpu_extra_caps & X86_EXTRA_CAP(group_id)) != 0
        : (decoder->cpu_extra_caps_high
            & X86_EXTRA_CAP_HIGH(group_id)) != 0;
}

static void decoder_require_extra_any(
    x86_decoder *decoder,
    cdisasm_x86_group_id first,
    cdisasm_x86_group_id second)
{
    const int use_second = decoder->cpu_id != CDISASM_CPU_X86
        && !decoder_has_extra(decoder, first)
        && decoder_has_extra(decoder, second);
    const cdisasm_x86_group_id used = use_second ? second : first;

    if (first < X86_EXTRA_GROUP_HIGH_BASE) {
        decoder->required_extra_any_caps |= X86_EXTRA_CAP(first);
    } else {
        decoder->required_extra_any_caps_high |= X86_EXTRA_CAP_HIGH(first);
    }
    if (second < X86_EXTRA_GROUP_HIGH_BASE) {
        decoder->required_extra_any_caps |= X86_EXTRA_CAP(second);
    } else {
        decoder->required_extra_any_caps_high |= X86_EXTRA_CAP_HIGH(second);
    }
    /* Report the actual profile path, not both mutually alternative ISA
     * gates.  The unrestricted profile uses the established first family as
     * its canonical classification. */
    if (used < X86_EXTRA_GROUP_HIGH_BASE) {
        decoder->used_extra_groups |= X86_EXTRA_CAP(used);
    } else {
        decoder->used_extra_groups_high |= X86_EXTRA_CAP_HIGH(used);
    }
}

static void decoder_require_evex_foundation(
    x86_decoder *decoder,
    int require_avx512vl,
    int allow_avx10)
{
    const uint64_t avx512f =
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512F);
    const uint64_t avx512vl =
        X86_EXTRA_CAP(CDISASM_X86_GROUP_AVX512VL);
    const int has_avx512_route = decoder->cpu_id == CDISASM_CPU_X86
        || ((decoder->cpu_extra_caps & avx512f) != 0
            && (!require_avx512vl
                || (decoder->cpu_extra_caps & avx512vl) != 0));

    /* Prefer the established AVX-512 classification when the selected
     * profile genuinely has that complete width route.  Abstract AVX10/APX
     * profiles instead report only AVX10.1; AVX512VL is not an AVX10
     * prerequisite even though both routes share the EVEX byte encoding. */
    if (has_avx512_route || !allow_avx10) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX512F);
        if (require_avx512vl) {
            decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX512VL);
        }
    } else {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX10_1);
    }
}

static void decoder_require_evex_packed_integer_foundation(
    x86_decoder *decoder,
    cdisasm_x86_group_id feature_group,
    int require_avx512vl)
{
    const int has_legacy_route = decoder->cpu_id == CDISASM_CPU_X86
        || (decoder_has_extra(decoder, CDISASM_X86_GROUP_AVX512F)
            && (!require_avx512vl
                || decoder_has_extra(
                    decoder, CDISASM_X86_GROUP_AVX512VL))
            && (feature_group == CDISASM_X86_GROUP_AVX512F
                || decoder_has_extra(decoder, feature_group)));

    /* AVX10.1 promotes these implemented packed-integer rows, including
     * their DQ/BW/VBMI/VNNI/CD functional slices, as a single alternate
     * route.  Do not make an AVX10 profile depend on a legacy AVX-512 CPUID
     * bit merely because that bit names the original encoding family. */
    if (has_legacy_route) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX512F);
        if (require_avx512vl) {
            decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX512VL);
        }
        if (feature_group != CDISASM_X86_GROUP_AVX512F) {
            decoder_require_extra(decoder, feature_group);
        }
    } else {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX10_1);
    }
}

static void decoder_require_evex_fp16_foundation(
    x86_decoder *decoder,
    int require_avx512vl)
{
    const int has_legacy_route = decoder->cpu_id == CDISASM_CPU_X86
        || (decoder_has_extra(decoder, CDISASM_X86_GROUP_AVX512F)
            && decoder_has_extra(
                decoder, CDISASM_X86_GROUP_AVX512FP16)
            && (!require_avx512vl
                || decoder_has_extra(
                    decoder, CDISASM_X86_GROUP_AVX512VL)));

    /* Legacy packed 128-/256-bit AVX512-FP16 forms also require AVX512VL;
     * scalar and packed 512-bit forms do not.  AVX10.1 promotes all four
     * ISA sets through their MAP5/MAP6 EVEX encodings, so an abstract AVX10
     * profile reports that one alternate route rather than legacy CPUID
     * groups. */
    if (has_legacy_route) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX512F);
        if (require_avx512vl) {
            decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX512VL);
        }
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX512FP16);
    } else {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX10_1);
    }
}

static void decoder_require_kmask_foundation(
    x86_decoder *decoder,
    cdisasm_x86_group_id feature_group)
{
    const int has_legacy_route = decoder->cpu_id == CDISASM_CPU_X86
        || (decoder_has_extra(decoder, CDISASM_X86_GROUP_AVX512F)
            && (feature_group == CDISASM_X86_GROUP_AVX512F
                || decoder_has_extra(decoder, feature_group)));

    /* AVX10.1 promotes the complete classic VEX K-opcode family without
     * requiring legacy AVX512F/DQ/BW CPUID bits.  Keep legacy AVX-512 as the
     * canonical unrestricted/physical-profile classification, but select a
     * single AVX10.1 route for abstract AVX10/APX profiles. */
    if (has_legacy_route) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX512F);
        if (feature_group != CDISASM_X86_GROUP_AVX512F) {
            decoder_require_extra(decoder, feature_group);
        }
    } else {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX10_1);
    }
}
#endif

static int decoder_has_caps(const x86_decoder *decoder, uint64_t caps)
{
    return (decoder->cpu_caps & caps) == caps;
}

static int cpu_uses_short_ud0(cdisasm_cpu_id cpu_id)
{
    /*
     * Intel XED models Pentium Pro and Atom-family chips with the two-byte
     * PPRO_UD0_SHORT form.  The unrestricted profile deliberately follows
     * the modern long form so its byte consumption is deterministic.
     */
    return cpu_id == CDISASM_CPU_PENTIUM_PRO
        || cpu_id == CDISASM_CPU_GOLDMONT
        || cpu_id == CDISASM_CPU_CELERON_N3350
        || cpu_id == CDISASM_CPU_CELERON_N4020
        || cpu_id == CDISASM_CPU_PENTIUM_SILVER_N6000;
}

static void decoder_require_caps(x86_decoder *decoder, uint64_t caps)
{
    decoder->required_caps |= caps;
}

#if USE_EXTRA_OPCODES
static void decoder_require_hle_or_rtm(x86_decoder *decoder)
{
    const uint64_t rtm = X86_EXTRA_CAP(CDISASM_X86_GROUP_RTM);

    /* XTEST is available when either CPUID.HLE or CPUID.RTM is set.  Keep RTM
     * as the canonical classification for unrestricted/RTM profiles, but use
     * the real HLE path for profiles on which RTM has been removed. */
    if (decoder->cpu_id != CDISASM_CPU_X86
        && (decoder->cpu_extra_caps & rtm) == 0
        && (decoder->cpu_caps & X86_CAP_HLE) != 0) {
        decoder_require_caps(decoder, X86_CAP_HLE);
    } else {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_RTM);
    }
}
#endif

static cdisasm_x86_reg_id gpr_id(
    unsigned int index,
    unsigned int bits,
    int rex_present)
{
    if (index >= 32) {
        return CDISASM_REG_NONE;
    }
    if (index >= 16) {
        switch (bits) {
            case 8:
                return (cdisasm_x86_reg_id)(
                    CDISASM_X86_REG_R16B + index - 16);
            case 16:
                return (cdisasm_x86_reg_id)(
                    CDISASM_X86_REG_R16W + index - 16);
            case 32:
                return (cdisasm_x86_reg_id)(
                    CDISASM_X86_REG_R16D + index - 16);
            case 64:
                return (cdisasm_x86_reg_id)(
                    CDISASM_X86_REG_R16 + index - 16);
            default:
                return CDISASM_REG_NONE;
        }
    }
    switch (bits) {
        case 8:
            if (index < 4) {
                return (cdisasm_x86_reg_id)(CDISASM_X86_REG_AL + index);
            }
            if (index < 8) {
                return (cdisasm_x86_reg_id)((rex_present
                    ? CDISASM_X86_REG_SPL
                    : CDISASM_X86_REG_AH)
                    + index - 4);
            }
            return (cdisasm_x86_reg_id)(CDISASM_X86_REG_R8B + index - 8);
        case 16:
            return (cdisasm_x86_reg_id)(CDISASM_X86_REG_AX + index);
        case 32:
            return (cdisasm_x86_reg_id)(CDISASM_X86_REG_EAX + index);
        case 64:
            return (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index);
        default:
            return CDISASM_REG_NONE;
    }
}

static cdisasm_x86_reg_id mmx_id(unsigned int index)
{
    return index < 8
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_MM0 + index)
        : CDISASM_REG_NONE;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id bnd_id(unsigned int index)
{
    return index < 4
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_BND0 + index)
        : CDISASM_X86_REG_NONE;
}
#endif

static cdisasm_x86_reg_id xmm_id(unsigned int index)
{
    return index < 32
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index)
        : CDISASM_REG_NONE;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_id(unsigned int index, unsigned int bits)
{
    if (index >= 32) {
        return CDISASM_REG_NONE;
    }
    if (bits == 128) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index);
    }
    if (bits == 256) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_YMM0 + index);
    }
    if (bits == 512) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + index);
    }
    return CDISASM_REG_NONE;
}
#endif

static cdisasm_x86_reg_id segment_id(unsigned int index)
{
    return index < 6
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_ES + index)
        : CDISASM_REG_NONE;
}

static cdisasm_x86_reg_id segment_prefix_id(uint8_t prefix)
{
    switch (prefix) {
        case 0x26:
            return CDISASM_REG_ES;
        case 0x2e:
            return CDISASM_REG_CS;
        case 0x36:
            return CDISASM_REG_SS;
        case 0x3e:
            return CDISASM_REG_DS;
        case 0x64:
            return CDISASM_REG_FS;
        case 0x65:
            return CDISASM_REG_GS;
        default:
            return CDISASM_REG_NONE;
    }
}

static int decoder_fail(x86_decoder *decoder, cdisasm_status status)
{
    if (decoder->error == CDISASM_STATUS_OK) {
        decoder->error = status;
    }
    return 0;
}

static int decoder_require(x86_decoder *decoder, size_t count)
{
    if (count > CDISASM_MAX_INSTRUCTION_SIZE - decoder->position) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (count > decoder->code_size - decoder->position) {
        return decoder_fail(decoder, CDISASM_STATUS_TRUNCATED);
    }
    return 1;
}

static int read_u8(x86_decoder *decoder, uint8_t *value)
{
    if (!decoder_require(decoder, 1)) {
        return 0;
    }
    *value = decoder->code[decoder->position++];
    return 1;
}

static int read_value(x86_decoder *decoder, unsigned int bits, uint64_t *value)
{
    size_t count = bits / 8;
    size_t index;
    uint64_t result = 0;

    if ((bits != 8 && bits != 16 && bits != 32 && bits != 64)
        || !decoder_require(decoder, count)) {
        return 0;
    }
    for (index = 0; index < count; ++index) {
        result |= (uint64_t)decoder->code[decoder->position + index] << (index * 8);
    }
    decoder->position += count;
    *value = result;
    return 1;
}

static int read_immediate_value(
    x86_decoder *decoder,
    unsigned int bits,
    uint64_t *value)
{
    uint8_t index;
    size_t offset = decoder->position;

    if (decoder->encoding.immediate_count >= 2) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    if (!read_value(decoder, bits, value)) {
        return 0;
    }
    index = decoder->encoding.immediate_count++;
    decoder->encoding.immediate_offset[index] = (uint8_t)offset;
    decoder->encoding.immediate_size[index] = (uint8_t)(bits / 8u);
    return 1;
}

static int read_displacement_value(
    x86_decoder *decoder,
    unsigned int bits,
    uint64_t *value)
{
    size_t offset = decoder->position;

    if (decoder->encoding.displacement_size != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    if (!read_value(decoder, bits, value)) {
        return 0;
    }
    decoder->encoding.displacement_offset = (uint8_t)offset;
    decoder->encoding.displacement_size = (uint8_t)(bits / 8u);
    return 1;
}

static int64_t sign_extend(uint64_t value, unsigned int bits)
{
    if (bits == 64) {
        return (int64_t)value;
    }
    return (int64_t)((value ^ (UINT64_C(1) << (bits - 1)))
        - (UINT64_C(1) << (bits - 1)));
}

static int add_typed_operand(
    x86_decoder *decoder,
    const x86_operand *metadata)
{
    x86_operand *operand;

    if (decoder->operand_count >= X86_MAX_OPERANDS) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    operand = &decoder->operand[decoder->operand_count];
    *operand = (x86_operand){0};
    if (metadata != NULL) {
        operand->type = metadata->type;
        operand->reg = metadata->reg;
        operand->base_reg = metadata->base_reg;
        operand->index_reg = metadata->index_reg;
        operand->size = metadata->size;
        operand->scale = metadata->scale;
        operand->segment_reg = metadata->segment_reg;
        operand->flags = metadata->flags;
        operand->address = metadata->address;
        operand->imm = metadata->imm;
        operand->resolve_pc_address = metadata->resolve_pc_address;
        operand->access = metadata->access;
        operand->broadcast = metadata->broadcast;
    }
    ++decoder->operand_count;
    return 1;
}

static int add_named_register_operand(
    x86_decoder *decoder,
    cdisasm_x86_reg_id register_id,
    unsigned int bits,
    uint8_t flags)
{
    x86_operand metadata = {0};

    metadata.type = CDISASM_OPERAND_REGISTER;
    metadata.reg = register_id;
    metadata.size = (uint8_t)((bits + 7u) / 8u);
    metadata.flags = flags;
    return add_typed_operand(decoder, &metadata);
}

static int add_named_register_operand_access(
    x86_decoder *decoder,
    cdisasm_x86_reg_id register_id,
    unsigned int bits,
    cdisasm_operand_access access)
{
    x86_operand metadata = {0};

    metadata.type = CDISASM_OPERAND_REGISTER;
    metadata.reg = register_id;
    metadata.size = (uint8_t)((bits + 7u) / 8u);
    metadata.access = (uint8_t)access;
    return add_typed_operand(decoder, &metadata);
}

static int set_last_operand_access(
    x86_decoder *decoder,
    cdisasm_operand_access access)
{
    if (decoder->operand_count == 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->operand[decoder->operand_count - 1].access = (uint8_t)access;
    return 1;
}

static int add_register_operand_flags(
    x86_decoder *decoder,
    unsigned int index,
    unsigned int bits,
    uint8_t flags)
{
    cdisasm_x86_reg_id register_id = gpr_id(
        index, bits, decoder->rex_present || decoder->rex2_present);

    if (register_id == CDISASM_REG_NONE) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    return add_named_register_operand(decoder, register_id, bits, flags);
}

static int add_register_operand(x86_decoder *decoder, unsigned int index, unsigned int bits)
{
    return add_register_operand_flags(decoder, index, bits, 0);
}

static int add_register_operand_access(
    x86_decoder *decoder,
    unsigned int index,
    unsigned int bits,
    cdisasm_operand_access access)
{
    if (!add_register_operand(decoder, index, bits)) {
        return 0;
    }
    return set_last_operand_access(decoder, access);
}

static int add_immediate_value(
    x86_decoder *decoder,
    unsigned int encoded_bits,
    uint64_t value,
    uint8_t flags)
{
    x86_operand metadata = {0};

    metadata.type = CDISASM_OPERAND_IMMEDIATE;
    metadata.size = (uint8_t)(encoded_bits / 8u);
    metadata.flags = flags;
    metadata.imm = value;
    return add_typed_operand(decoder, &metadata);
}

static int add_memory_operand(
    x86_decoder *decoder,
    unsigned int bits,
    cdisasm_x86_reg_id base_reg,
    cdisasm_x86_reg_id index_reg,
    uint8_t scale,
    cdisasm_x86_reg_id segment_reg,
    uint8_t flags,
    uint64_t address,
    uint64_t displacement)
{
    x86_operand metadata = {0};

    metadata.type = CDISASM_OPERAND_MEMORY;
    metadata.base_reg = base_reg;
    metadata.index_reg = index_reg;
    metadata.size = (uint8_t)((bits + 7u) / 8u);
    metadata.scale = index_reg == CDISASM_REG_NONE ? 0 : scale;
    metadata.segment_reg = segment_reg;
    metadata.flags = flags;
    metadata.address = address;
    metadata.imm = displacement;
    return add_typed_operand(decoder, &metadata);
}

static int add_segment_register_operand(x86_decoder *decoder, unsigned int index)
{
    cdisasm_x86_reg_id register_id = segment_id(index);

    if (index >= 6 || register_id == CDISASM_REG_NONE) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    return add_named_register_operand(
        decoder,
        register_id,
        16,
        0);
}

static int add_immediate_operand(
    x86_decoder *decoder,
    unsigned int encoded_bits,
    int signed_text)
{
    uint64_t value;
    uint64_t semantic_value;

    if (!read_immediate_value(decoder, encoded_bits, &value)) {
        return 0;
    }
    if (signed_text) {
        semantic_value = (uint64_t)sign_extend(value, encoded_bits);
    } else {
        semantic_value = value;
    }
    return add_immediate_value(
        decoder,
        encoded_bits,
        semantic_value,
        signed_text ? CDISASM_OPERAND_FLAG_SIGNED : 0);
}

static int add_relative_operand(x86_decoder *decoder, unsigned int encoded_bits)
{
    uint64_t encoded;
    int64_t displacement;
    uint64_t target;
    x86_operand metadata = {0};

    if (!read_immediate_value(decoder, encoded_bits, &encoded)) {
        return 0;
    }
    displacement = sign_extend(encoded, encoded_bits);
    target = decoder->address + decoder->position + (uint64_t)displacement;
    decoder->branch_target = target;
    metadata.type = CDISASM_OPERAND_IMMEDIATE;
    metadata.size = (uint8_t)(encoded_bits / 8u);
    metadata.flags = CDISASM_OPERAND_FLAG_SIGNED
        | CDISASM_OPERAND_FLAG_PC_RELATIVE
        | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
    metadata.address = (uint64_t)displacement;
    metadata.imm = target;
    return add_typed_operand(decoder, &metadata);
}

static int parse_prefixes(x86_decoder *decoder)
{
    for (;;) {
        uint8_t byte;
        int legacy = 1;

        if (decoder->position >= CDISASM_MAX_INSTRUCTION_SIZE) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (decoder->position >= decoder->code_size) {
            return decoder_fail(decoder, CDISASM_STATUS_TRUNCATED);
        }

        byte = decoder->code[decoder->position];
        switch (byte) {
            case 0xf0:
                decoder->prefix_flags |= CDISASM_PREFIX_LOCK;
                decoder->lock_prefix = 1;
                break;
            case 0xf2:
                decoder->prefix_flags |= CDISASM_PREFIX_REPNE;
                decoder->repeat_prefix = byte;
                break;
            case 0xf3:
                decoder->prefix_flags |= CDISASM_PREFIX_REP;
                decoder->repeat_prefix = byte;
                break;
            case 0x66:
                decoder->prefix_flags |= CDISASM_PREFIX_OPERAND_SIZE;
                decoder->operand_override = 1;
                break;
            case 0x67:
                decoder->prefix_flags |= CDISASM_PREFIX_ADDRESS_SIZE;
                decoder->address_override = 1;
                break;
            case 0x26:
            case 0x2e:
            case 0x36:
            case 0x3e:
            case 0x64:
            case 0x65:
                decoder->prefix_flags |= CDISASM_PREFIX_SEGMENT;
                decoder->segment_prefix = byte;
                break;
            default:
                legacy = 0;
                break;
        }

        if (legacy) {
            if (byte == 0x66 || byte == 0x67 || byte == 0x64 || byte == 0x65) {
                decoder_require_caps(decoder, X86_CAP_80386);
            }
            ++decoder->position;
            /* A legacy prefix after a REX makes that earlier REX ineffective. */
            decoder->rex = 0;
            decoder->rex_present = 0;
            decoder->prefix_flags &= ~CDISASM_PREFIX_REX_W;
            continue;
        }

        if (decoder->mode == CDISASM_MODE_64 && byte >= 0x40 && byte <= 0x4f) {
            decoder->rex = byte;
            decoder->rex_present = 1;
            decoder->prefix_flags |= CDISASM_PREFIX_REX;
            if ((byte & 8u) != 0) {
                decoder->prefix_flags |= CDISASM_PREFIX_REX_W;
            } else {
                decoder->prefix_flags &= ~CDISASM_PREFIX_REX_W;
            }
            ++decoder->position;
            continue;
        }
        if (decoder->mode == CDISASM_MODE_64 && byte == UINT8_C(0xd5)) {
            uint8_t payload;

            if (decoder->rex_present || decoder->rex2_present) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            if (!decoder_require(decoder, 2)) {
                return 0;
            }
            payload = decoder->code[decoder->position + 1];
            decoder->position += 2;
            decoder->rex2_present = 1;
            decoder->rex2_map = (payload >> 7) & 1u;
            decoder->rex = payload & UINT8_C(0x0f);
            decoder->modrm_reg_high = (payload & UINT8_C(0x40)) != 0
                ? 16u : 0u;
            decoder->address_index_high =
                (payload & UINT8_C(0x20)) != 0 ? 16u : 0u;
            decoder->modrm_rm_high = (payload & UINT8_C(0x10)) != 0
                ? 16u : 0u;
            decoder->address_base_high = decoder->modrm_rm_high;
            decoder->prefix_flags |= CDISASM_PREFIX_REX2;
            if ((payload & UINT8_C(0x08)) != 0) {
                decoder->prefix_flags |= CDISASM_PREFIX_REX_W;
            }
            /* REX2, like REX, is the final prefix before the opcode. */
            break;
        }
        break;
    }

    if (decoder->mode == CDISASM_MODE_16) {
        decoder->operand_bits = decoder->operand_override ? 32u : 16u;
        decoder->address_bits = decoder->address_override ? 32u : 16u;
    } else if (decoder->mode == CDISASM_MODE_32) {
        decoder->operand_bits = decoder->operand_override ? 16u : 32u;
        decoder->address_bits = decoder->address_override ? 16u : 32u;
    } else {
        decoder->operand_bits = decoder->operand_override ? 16u : 32u;
        if ((decoder->rex & 8u) != 0) {
            decoder->operand_bits = 64u;
        }
        decoder->address_bits = decoder->address_override ? 32u : 64u;
    }
    return 1;
}

static int decode_modrm(x86_decoder *decoder, x86_modrm *result)
{
    uint8_t byte;
    size_t modrm_offset = decoder->position;

    *result = (x86_modrm){0};
    result->base = -1;
    result->index = -1;
    result->scale = 1;

    if (!read_u8(decoder, &byte)) {
        return 0;
    }
    decoder->encoding.modrm_offset = (uint8_t)modrm_offset;
    decoder->encoding.modrm = byte;
    result->mod = (uint8_t)(byte >> 6);
    result->reg3 = (uint8_t)((byte >> 3) & 7);
    result->rm3 = (uint8_t)(byte & 7);
    result->reg = (uint8_t)(result->reg3
        + ((decoder->rex & 4u) ? 8u : 0u)
        + decoder->modrm_reg_high);
    result->rm = (uint8_t)(result->rm3
        + ((decoder->rex & 1u) ? 8u : 0u)
        + decoder->modrm_rm_high);

    if (result->mod == 3) {
        result->is_register = 1;
        return 1;
    }

    if (decoder->address_bits == 16) {
        static const int base_table[8] = {3, 3, 5, 5, 6, 7, 5, 3};
        static const int index_table[8] = {6, 7, 6, 7, -1, -1, -1, -1};

        if (result->mod == 0 && result->rm3 == 6) {
            uint64_t displacement;
            if (!read_displacement_value(decoder, 16, &displacement)) {
                return 0;
            }
            result->absolute = 1;
            result->has_displacement = 1;
            result->displacement_raw = displacement;
            result->displacement = (int64_t)displacement;
        } else {
            result->base = base_table[result->rm3];
            result->index = index_table[result->rm3];
        }
    } else if (result->rm3 == 4) {
        uint8_t sib;
        uint8_t index3;
        uint8_t base3;

        decoder->encoding.sib_offset = (uint8_t)decoder->position;
        if (!read_u8(decoder, &sib)) {
            return 0;
        }
        decoder->encoding.sib = sib;
        result->scale = 1u << (sib >> 6);
        index3 = (uint8_t)((sib >> 3) & 7);
        base3 = (uint8_t)(sib & 7);

        if (index3 != 4 || (decoder->rex & 2u) != 0
            || decoder->address_index_high != 0) {
            result->index = index3 + ((decoder->rex & 2u) ? 8 : 0)
                + decoder->address_index_high;
        }
        /* mod=00/SIB.base=101 is the disp32 no-base sentinel.  REX.B and
         * REX2.B4 do not turn that reserved base field into r13/r21; the
         * extension bits only apply when the base field names a register. */
        if (result->mod == 0 && base3 == 5) {
            uint64_t displacement;
            if (!read_displacement_value(decoder, 32, &displacement)) {
                return 0;
            }
            result->absolute = 1;
            result->has_displacement = 1;
            result->displacement_raw = displacement;
            result->displacement = sign_extend(displacement, 32);
        } else {
            result->base = base3 + ((decoder->rex & 1u) ? 8 : 0)
                + decoder->address_base_high;
        }
    } else if (result->mod == 0 && result->rm3 == 5) {
        uint64_t displacement;
        if (!read_displacement_value(decoder, 32, &displacement)) {
            return 0;
        }
        result->has_displacement = 1;
        result->displacement_raw = displacement;
        result->displacement = sign_extend(displacement, 32);
        if (decoder->mode == CDISASM_MODE_64) {
            result->rip_relative = 1;
        } else {
            result->absolute = 1;
        }
    } else {
        result->base = result->rm;
    }

    if (result->mod == 1) {
        uint64_t displacement;
        if (!read_displacement_value(decoder, 8, &displacement)) {
            return 0;
        }
        result->has_displacement = 1;
        result->displacement_raw = displacement;
        result->displacement = sign_extend(displacement, 8);
    } else if (result->mod == 2) {
        uint64_t displacement;
        unsigned int bits = decoder->address_bits == 16 ? 16u : 32u;
        if (!read_displacement_value(decoder, bits, &displacement)) {
            return 0;
        }
        result->has_displacement = 1;
        result->displacement_raw = displacement;
        result->displacement = sign_extend(displacement, bits);
    }
    return 1;
}

static int add_rm_operand(
    x86_decoder *decoder,
    const x86_modrm *modrm,
    unsigned int bits,
    int show_pointer)
{
    x86_operand metadata = {0};

    if (modrm->is_register) {
        return add_register_operand(decoder, modrm->rm, bits);
    }

    metadata.type = CDISASM_OPERAND_MEMORY;
    metadata.size = (uint8_t)((bits + 7u) / 8u);
    if (modrm->base >= 0) {
        metadata.base_reg = gpr_id(
            (unsigned int)modrm->base,
            decoder->address_bits,
            1);
    }
    if (modrm->index >= 0) {
        metadata.index_reg = gpr_id(
            (unsigned int)modrm->index,
            decoder->address_bits,
            1);
        metadata.scale = (uint8_t)modrm->scale;
    }
    if (modrm->rip_relative) {
        metadata.base_reg = decoder->address_bits == 32
            ? CDISASM_REG_EIP
            : CDISASM_REG_RIP;
        metadata.flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
        metadata.resolve_pc_address = 1;
    }
    if (modrm->has_displacement) {
        metadata.flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
        metadata.imm = (uint64_t)modrm->displacement;
    }
    if (modrm->absolute && modrm->index < 0) {
        metadata.flags |= CDISASM_OPERAND_FLAG_ABSOLUTE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
        metadata.address = decoder->address_bits == 64
            ? (uint64_t)modrm->displacement
            : modrm->displacement_raw;
    }
    if (!show_pointer) {
        metadata.flags |= CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
    }
    metadata.segment_reg = segment_prefix_id(decoder->segment_prefix);
    if (metadata.segment_reg != CDISASM_REG_NONE) {
        metadata.flags |= CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
    }
    return add_typed_operand(decoder, &metadata);
}

#if USE_EXTRA_OPCODES
static int add_movdir64b_operands(
    x86_decoder *decoder,
    const x86_modrm *modrm)
{
    const cdisasm_x86_reg_id destination_base = gpr_id(
        modrm->reg, decoder->address_bits, 1);
    const cdisasm_x86_reg_id destination_segment =
        decoder->mode == CDISASM_MODE_64
        ? CDISASM_X86_REG_NONE
        : CDISASM_X86_REG_ES;

    if (destination_base == CDISASM_X86_REG_NONE) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!add_register_operand_access(
            decoder, modrm->reg, decoder->address_bits,
            CDISASM_OPERAND_ACCESS_READ)
        || !add_rm_operand(decoder, modrm, 512u, 1)
        || !set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ)
        || !add_memory_operand(
            decoder, 512u, destination_base, CDISASM_X86_REG_NONE,
            0, destination_segment, CDISASM_OPERAND_FLAG_IMPLICIT,
            0, 0)) {
        return 0;
    }
    return set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_WRITE);
}

static int add_vector_register_operand_access(
    x86_decoder *decoder,
    unsigned int index,
    unsigned int bits,
    cdisasm_operand_access access)
{
    cdisasm_x86_reg_id register_id = vector_id(index, bits);

    if (register_id == CDISASM_REG_NONE) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    return add_named_register_operand_access(
        decoder, register_id, bits, access);
}

static int add_mask_register_operand_access(
    x86_decoder *decoder,
    unsigned int index,
    unsigned int bits,
    cdisasm_operand_access access)
{
    if (index >= 8) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    return add_named_register_operand_access(
        decoder,
        (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + index),
        bits,
        access);
}

static int add_bnd_register_operand_access(
    x86_decoder *decoder,
    unsigned int index,
    cdisasm_operand_access access)
{
    const cdisasm_x86_reg_id reg = bnd_id(index);
    const unsigned int bits = decoder->mode == CDISASM_MODE_64 ? 128u : 64u;

    if (reg == CDISASM_X86_REG_NONE) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    return add_named_register_operand_access(decoder, reg, bits, access);
}

static int add_vector_rm_operand_access(
    x86_decoder *decoder,
    const x86_modrm *modrm,
    unsigned int register_bits,
    unsigned int memory_bits,
    cdisasm_operand_access access)
{
    if (modrm->is_register) {
        return add_vector_register_operand_access(
            decoder, modrm->rm, register_bits, access);
    }
    if (!add_rm_operand(decoder, modrm, memory_bits, 1)) {
        return 0;
    }
    return set_last_operand_access(decoder, access);
}

static int add_tile_register_operand_access(
    x86_decoder *decoder,
    unsigned int index,
    cdisasm_operand_access access)
{
    x86_operand metadata = {0};

    if (index >= 8) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    metadata.type = CDISASM_OPERAND_REGISTER;
    metadata.reg = (cdisasm_x86_reg_id)(CDISASM_X86_REG_TMM0 + index);
    /* AMX tile shape is configured at run time; 0xff is the ABI sentinel. */
    metadata.size = UINT8_MAX;
    metadata.access = (uint8_t)access;
    return add_typed_operand(decoder, &metadata);
}
#endif

static int decode_binary_rm_reg(
    x86_decoder *decoder,
    cdisasm_x86_name_id name_id,
    unsigned int bits,
    int register_first,
    int lockable)
{
    x86_modrm modrm;

    decoder->name_id = name_id;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (lockable && !modrm.is_register) {
        decoder->lock_allowed = 1;
    }
    if (register_first) {
        return add_register_operand(decoder, modrm.reg, bits)
            && add_rm_operand(decoder, &modrm, bits, 1);
    }
    return add_rm_operand(decoder, &modrm, bits, 1)
        && add_register_operand(decoder, modrm.reg, bits);
}

static int decode_alu(x86_decoder *decoder, uint8_t opcode)
{
    static const cdisasm_x86_name_id name_ids[8] = {
        CDISASM_X86_NAME_ADD, CDISASM_X86_NAME_OR,
        CDISASM_X86_NAME_ADC, CDISASM_X86_NAME_SBB,
        CDISASM_X86_NAME_AND, CDISASM_X86_NAME_SUB,
        CDISASM_X86_NAME_XOR, CDISASM_X86_NAME_CMP
    };
    unsigned int operation = opcode >> 3;
    unsigned int form = opcode & 7;
    unsigned int bits;

    if (opcode > 0x3d || operation >= 8 || form > 5) {
        return 0;
    }

    bits = (form == 0 || form == 2 || form == 4) ? 8u : decoder->operand_bits;
    decoder->name_id = name_ids[operation];

    if (form <= 3) {
        return decode_binary_rm_reg(
            decoder,
            name_ids[operation],
            bits,
            form >= 2,
            operation != 7 && form < 2);
    }

    if (!add_register_operand(decoder, 0, bits)) {
        return 0;
    }
    return add_immediate_operand(
        decoder,
        bits == 64 ? 32u : bits,
        bits == 64);
}

static int decode_group1(x86_decoder *decoder, uint8_t opcode)
{
    static const cdisasm_x86_name_id name_ids[8] = {
        CDISASM_X86_NAME_ADD, CDISASM_X86_NAME_OR,
        CDISASM_X86_NAME_ADC, CDISASM_X86_NAME_SBB,
        CDISASM_X86_NAME_AND, CDISASM_X86_NAME_SUB,
        CDISASM_X86_NAME_XOR, CDISASM_X86_NAME_CMP
    };
    x86_modrm modrm;
    unsigned int bits = (opcode == 0x80 || opcode == 0x82)
        ? 8u
        : decoder->operand_bits;
    unsigned int immediate_bits;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = name_ids[modrm.reg3];
    if (modrm.reg3 != 7 && !modrm.is_register) {
        decoder->lock_allowed = 1;
    }
    if (!add_rm_operand(decoder, &modrm, bits, 1)) {
        return 0;
    }

    if (opcode == 0x80 || opcode == 0x82 || opcode == 0x83) {
        immediate_bits = 8;
    } else {
        immediate_bits = bits == 64 ? 32u : bits;
    }
    return add_immediate_operand(
        decoder,
        immediate_bits,
        opcode == 0x83 || bits == 64);
}

static int decode_group2(x86_decoder *decoder, uint8_t opcode)
{
    static const cdisasm_x86_name_id name_ids[8] = {
        CDISASM_X86_NAME_ROL, CDISASM_X86_NAME_ROR,
        CDISASM_X86_NAME_RCL, CDISASM_X86_NAME_RCR,
        CDISASM_X86_NAME_SHL, CDISASM_X86_NAME_SHR,
        CDISASM_X86_NAME_SHL, CDISASM_X86_NAME_SAR
    };
    x86_modrm modrm;
    unsigned int bits = (opcode == 0xc0 || opcode == 0xd0 || opcode == 0xd2)
        ? 8u
        : decoder->operand_bits;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.reg3 == 6) {
        decoder_require_caps(decoder, X86_CAP_80186);
    }
    decoder->name_id = name_ids[modrm.reg3];
    if (!add_rm_operand(decoder, &modrm, bits, 1)) {
        return 0;
    }
    if (opcode == 0xc0 || opcode == 0xc1) {
        decoder_require_caps(decoder, X86_CAP_80186);
        return add_immediate_operand(decoder, 8, 0);
    }
    if (opcode == 0xd0 || opcode == 0xd1) {
        return add_immediate_value(
            decoder,
            0,
            1,
            CDISASM_OPERAND_FLAG_IMPLICIT);
    }
    return add_named_register_operand(
        decoder,
        CDISASM_REG_CL,
        8,
        CDISASM_OPERAND_FLAG_IMPLICIT);
}

static int decode_group3(x86_decoder *decoder, uint8_t opcode)
{
    static const cdisasm_x86_name_id name_ids[8] = {
        CDISASM_X86_NAME_TEST, CDISASM_X86_NAME_TEST,
        CDISASM_X86_NAME_NOT, CDISASM_X86_NAME_NEG,
        CDISASM_X86_NAME_MUL, CDISASM_X86_NAME_IMUL,
        CDISASM_X86_NAME_DIV, CDISASM_X86_NAME_IDIV
    };
    x86_modrm modrm;
    unsigned int bits = opcode == 0xf6 ? 8u : decoder->operand_bits;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = name_ids[modrm.reg3];
    if ((modrm.reg3 == 2 || modrm.reg3 == 3) && !modrm.is_register) {
        decoder->lock_allowed = 1;
    }
    if (!add_rm_operand(decoder, &modrm, bits, 1)) {
        return 0;
    }
    if (modrm.reg3 <= 1) {
        return add_immediate_operand(decoder, bits == 64 ? 32u : bits, bits == 64);
    }
    return 1;
}

static int decode_imul_immediate(x86_decoder *decoder, uint8_t opcode)
{
    x86_modrm modrm;
    unsigned int immediate_bits = opcode == 0x6b
        ? 8u
        : (decoder->operand_bits == 64 ? 32u : decoder->operand_bits);

    decoder->name_id = CDISASM_X86_NAME_IMUL;
    decoder_require_caps(decoder, X86_CAP_80186);
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    return add_register_operand(decoder, modrm.reg, decoder->operand_bits)
        && add_rm_operand(decoder, &modrm, decoder->operand_bits, 1)
        && add_immediate_operand(
            decoder,
            immediate_bits,
            opcode == 0x6b || decoder->operand_bits == 64);
}

static int decode_push_pop_register(x86_decoder *decoder, uint8_t opcode)
{
    unsigned int register_index = (opcode & 7u) + ((decoder->rex & 1u) ? 8u : 0u);
    unsigned int bits = decoder->mode == CDISASM_MODE_64
        ? (decoder->operand_override ? 16u : 64u)
        : decoder->operand_bits;

    decoder->name_id = opcode < 0x58 ? CDISASM_X86_NAME_PUSH : CDISASM_X86_NAME_POP;
    return add_register_operand(decoder, register_index, bits);
}

static int decode_inc_dec_register(x86_decoder *decoder, uint8_t opcode)
{
    decoder->name_id = opcode < 0x48 ? CDISASM_X86_NAME_INC : CDISASM_X86_NAME_DEC;
    return add_register_operand(decoder, opcode & 7u, decoder->operand_bits);
}

static int decode_mov_immediate_register(x86_decoder *decoder, uint8_t opcode)
{
    unsigned int bits = opcode < 0xb8 ? 8u : decoder->operand_bits;
    unsigned int register_index = (opcode & 7u) + ((decoder->rex & 1u) ? 8u : 0u);
    unsigned int immediate_bits = bits;

    decoder->name_id = bits == 64 ? CDISASM_X86_NAME_MOVABS : CDISASM_X86_NAME_MOV;
    if (!add_register_operand(decoder, register_index, bits)) {
        return 0;
    }
    return add_immediate_operand(decoder, immediate_bits, 0);
}

static int decode_jcc(x86_decoder *decoder, unsigned int condition, unsigned int relative_bits)
{
    decoder->name_id = jump_condition_name[condition];
    decoder->groups |= CDISASM_GROUP_JUMP
        | CDISASM_GROUP_RELATIVE_BRANCH
        | CDISASM_GROUP_CONDITIONAL;
    return add_relative_operand(decoder, relative_bits);
}

static int decode_cmovcc(x86_decoder *decoder, unsigned int condition)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = move_condition_name[condition];
    decoder->groups |= CDISASM_GROUP_CONDITIONAL;
    return add_register_operand(decoder, modrm.reg, decoder->operand_bits)
        && add_rm_operand(decoder, &modrm, decoder->operand_bits, 1);
}

static int decode_setcc(x86_decoder *decoder, unsigned int condition)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = set_condition_name[condition];
    decoder->groups |= CDISASM_GROUP_CONDITIONAL;
    return add_rm_operand(decoder, &modrm, 8, 1);
}

static int decode_two_byte(x86_decoder *decoder);
static int decode_primary(x86_decoder *decoder, uint8_t opcode);
static int cpu_has_apx_f(cdisasm_x86_cpu_id cpu_id);

static int add_x86_group(
    cdisasm_instruction *instruction,
    cdisasm_x86_group_id group_id)
{
    uint8_t index = 0;
    uint8_t move;

    if (group_id < CDISASM_X86_GROUP_FIRST
        || group_id > CDISASM_X86_GROUP_LAST) {
        return 0;
    }
    while (index < instruction->x86_group_count
        && instruction->x86_group_ids[index] < group_id) {
        ++index;
    }
    if (index < instruction->x86_group_count
        && instruction->x86_group_ids[index] == group_id) {
        return 1;
    }
    if (instruction->x86_group_count >= CDISASM_MAX_X86_GROUPS) {
        return 0;
    }
    for (move = instruction->x86_group_count; move > index; --move) {
        instruction->x86_group_ids[move] =
            instruction->x86_group_ids[move - 1];
    }
    instruction->x86_group_ids[index] = group_id;
    ++instruction->x86_group_count;
    return 1;
}

static int add_register_form_groups(
    cdisasm_instruction *instruction,
    cdisasm_x86_reg_id register_id)
{
    if ((register_id >= CDISASM_X86_REG_EAX
            && register_id <= CDISASM_X86_REG_EDI)
        || register_id == CDISASM_X86_REG_EIP
        || register_id == CDISASM_X86_REG_FS
        || register_id == CDISASM_X86_REG_GS
        || (register_id >= CDISASM_X86_REG_CR0
            && register_id <= CDISASM_X86_REG_CR7)
        || (register_id >= CDISASM_X86_REG_DR0
            && register_id <= CDISASM_X86_REG_DR7)) {
        return add_x86_group(instruction, CDISASM_X86_GROUP_I386);
    }
    if ((register_id >= CDISASM_X86_REG_SPL
            && register_id <= CDISASM_X86_REG_R15B)
        || (register_id >= CDISASM_X86_REG_R8W
            && register_id <= CDISASM_X86_REG_R15W)
        || (register_id >= CDISASM_X86_REG_R8D
            && register_id <= CDISASM_X86_REG_R15D)
        || (register_id >= CDISASM_X86_REG_RAX
            && register_id <= CDISASM_X86_REG_R15)
        || (register_id >= CDISASM_X86_REG_XMM8
            && register_id <= CDISASM_X86_REG_XMM15)
        || (register_id >= CDISASM_X86_REG_YMM8
            && register_id <= CDISASM_X86_REG_YMM15)
        || register_id == CDISASM_X86_REG_RIP
        || (register_id >= CDISASM_X86_REG_CR8
            && register_id <= CDISASM_X86_REG_CR15)
        || (register_id >= CDISASM_X86_REG_DR8
            && register_id <= CDISASM_X86_REG_DR15)) {
        return add_x86_group(instruction, CDISASM_X86_GROUP_AMD64);
    }
    return 1;
}

static int add_name_form_groups(
    const x86_decoder *decoder,
    cdisasm_instruction *instruction,
    cdisasm_x86_name_id name_id)
{
    if (name_id == CDISASM_X86_NAME_MOVD
        || name_id == CDISASM_X86_NAME_MOVQ) {
        unsigned int operand_index;

        for (operand_index = 0;
             operand_index < instruction->operand_count;
             ++operand_index) {
            const cdisasm_opcode *operand =
                &instruction->opcode[operand_index];

            if (operand->type == CDISASM_OPERAND_REGISTER
                && operand->reg >= CDISASM_X86_REG_MM0
                && operand->reg <= CDISASM_X86_REG_MM7) {
                return add_x86_group(
                    instruction,
                    CDISASM_X86_GROUP_PENTIUMMMX);
            }
        }
    }
    if ((name_id == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
            || name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB
            || name_id == CDISASM_X86_NAME_VGF2P8MULB)
        && decoder->form_id >= UINT16_C(5505)
        && decoder->form_id <= UINT16_C(5534)) {
        const unsigned int family_offset =
            decoder->form_id - UINT16_C(5505);
        const unsigned int within_family = family_offset % 10u;

        /* The pinned XED catalog exposes one exact AVX_GFNI ISA set for
         * classic VEX and width-specific AVX512_GFNI sets for EVEX.  Keep
         * that identity in addition to the independent GFNI capability and
         * the selected AVX/EVEX foundation groups. */
        if (within_family == 2u || within_family == 3u
            || within_family == 6u || within_family == 7u) {
            return add_x86_group(
                instruction, CDISASM_X86_GROUP_AVX_GFNI);
        }
        return add_x86_group(
            instruction,
            within_family <= 1u
                ? CDISASM_X86_GROUP_AVX512_GFNI_128
                : within_family <= 5u
                    ? CDISASM_X86_GROUP_AVX512_GFNI_256
                    : CDISASM_X86_GROUP_AVX512_GFNI_512);
    }
    if ((decoder->form_id >= UINT16_C(5997)
            && decoder->form_id <= UINT16_C(6003))
        || (decoder->form_id >= UINT16_C(6048)
            && decoder->form_id <= UINT16_C(6053))) {
        /* These Intel virtualization identities are the exact pinned XED VTX
         * ISA_SET.  Keep that catalog identity in addition to the VMX
         * capability umbrella contributed by required_caps. */
        return add_x86_group(instruction, CDISASM_X86_GROUP_VTX);
    }
    if (name_id == CDISASM_X86_NAME_MOVNTDQA
        && decoder->form_id == UINT16_C(1690)) {
        /* XED names this historical SSE4.1-era row ISA_SET SSE4.  Preserve
         * that exact catalog identity separately from its SSE4.1 hardware
         * prerequisite. */
        return add_x86_group(instruction, CDISASM_X86_GROUP_SSE4);
    }
    if (name_id == CDISASM_X86_NAME_VMOVNTDQA
        && (decoder->form_id == UINT16_C(5865)
            || decoder->form_id == UINT16_C(5867)
            || decoder->form_id == UINT16_C(5868))) {
        return add_x86_group(
            instruction,
            decoder->form_id == UINT16_C(5865)
                ? CDISASM_X86_GROUP_AVX512F_128
                : decoder->form_id == UINT16_C(5867)
                    ? CDISASM_X86_GROUP_AVX512F_256
                    : CDISASM_X86_GROUP_AVX512F_512);
    }
    if ((name_id == CDISASM_X86_NAME_VMOVNTDQ
            && decoder->form_id >= UINT16_C(5871)
            && decoder->form_id <= UINT16_C(5873))
        || (name_id == CDISASM_X86_NAME_VMOVNTPD
            && decoder->form_id >= UINT16_C(5875)
            && decoder->form_id <= UINT16_C(5877))
        || (name_id == CDISASM_X86_NAME_VMOVNTPS
            && decoder->form_id >= UINT16_C(5880)
            && decoder->form_id <= UINT16_C(5882))) {
        unsigned int width_index;

        if (name_id == CDISASM_X86_NAME_VMOVNTDQ) {
            width_index = decoder->form_id - UINT16_C(5871);
        } else if (name_id == CDISASM_X86_NAME_VMOVNTPD) {
            width_index = decoder->form_id - UINT16_C(5875);
        } else {
            width_index = decoder->form_id - UINT16_C(5880);
        }
        return add_x86_group(
            instruction,
            width_index == 0u ? CDISASM_X86_GROUP_AVX512F_128
                : width_index == 1u ? CDISASM_X86_GROUP_AVX512F_256
                                    : CDISASM_X86_GROUP_AVX512F_512);
    }
    if (name_id == CDISASM_X86_NAME_VMOVQ
        && (decoder->form_id == UINT16_C(5885)
            || decoder->form_id == UINT16_C(5888)
            || (decoder->form_id >= UINT16_C(5894)
                && decoder->form_id <= UINT16_C(5896)))) {
        return add_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F_128N);
    }
    if ((name_id == CDISASM_X86_NAME_VMOVSHDUP
            && ((decoder->form_id >= UINT16_C(5918)
                    && decoder->form_id <= UINT16_C(5921))
                || decoder->form_id == UINT16_C(5924)
                || decoder->form_id == UINT16_C(5925)))
        || (name_id == CDISASM_X86_NAME_VMOVSLDUP
            && ((decoder->form_id >= UINT16_C(5931)
                    && decoder->form_id <= UINT16_C(5934))
                || decoder->form_id == UINT16_C(5937)
                || decoder->form_id == UINT16_C(5938)))) {
        cdisasm_x86_group_id width_group;

        if (decoder->form_id == UINT16_C(5918)
            || decoder->form_id == UINT16_C(5919)
            || decoder->form_id == UINT16_C(5931)
            || decoder->form_id == UINT16_C(5932)) {
            width_group = CDISASM_X86_GROUP_AVX512F_128;
        } else if (decoder->form_id == UINT16_C(5920)
            || decoder->form_id == UINT16_C(5921)
            || decoder->form_id == UINT16_C(5933)
            || decoder->form_id == UINT16_C(5934)) {
            width_group = CDISASM_X86_GROUP_AVX512F_256;
        } else {
            width_group = CDISASM_X86_GROUP_AVX512F_512;
        }
        return add_x86_group(instruction, width_group);
    }
    if (name_id == CDISASM_X86_NAME_VMOVSH
        && decoder->form_id >= UINT16_C(5926)
        && decoder->form_id <= UINT16_C(5928)) {
        return add_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512_FP16_SCALAR);
    }
    if (name_id == CDISASM_X86_NAME_VMOVW
        && decoder->form_id >= UINT16_C(5980)
        && decoder->form_id <= UINT16_C(5986)) {
        return add_x86_group(
            instruction,
            decoder->form_id == UINT16_C(5982)
                    || decoder->form_id == UINT16_C(5985)
                    || decoder->form_id == UINT16_C(5986)
                ? CDISASM_X86_GROUP_AVX512_MOVZXC_128
                : CDISASM_X86_GROUP_AVX512_FP16_128N);
    }
    if (name_id == CDISASM_X86_NAME_VDBPSADBW
        && decoder->form_id >= UINT16_C(4453)
        && decoder->form_id <= UINT16_C(4458)) {
        const unsigned int width_index =
            (decoder->form_id - UINT16_C(4453)) / 2u;

        return add_x86_group(
            instruction,
            width_index == 0u ? CDISASM_X86_GROUP_AVX512BW_128
                : width_index == 1u ? CDISASM_X86_GROUP_AVX512BW_256
                                    : CDISASM_X86_GROUP_AVX512BW_512);
    }
    if (name_id >= CDISASM_X86_NAME_VPTESTMB
        && name_id <= CDISASM_X86_NAME_VPTESTNMW
        && decoder->form_id >= UINT16_C(8271)
        && decoder->form_id <= UINT16_C(8318)) {
        unsigned int within_family =
            (decoder->form_id - UINT16_C(8271)) % 6u;
        unsigned int width_index = within_family / 2u;
        int bw = name_id == CDISASM_X86_NAME_VPTESTMB
            || name_id == CDISASM_X86_NAME_VPTESTMW
            || name_id == CDISASM_X86_NAME_VPTESTNMB
            || name_id == CDISASM_X86_NAME_VPTESTNMW;

        return add_x86_group(
            instruction,
            bw ? (width_index == 0u ? CDISASM_X86_GROUP_AVX512BW_128
                    : width_index == 1u
                        ? CDISASM_X86_GROUP_AVX512BW_256
                        : CDISASM_X86_GROUP_AVX512BW_512)
               : (width_index == 0u ? CDISASM_X86_GROUP_AVX512F_128
                    : width_index == 1u
                        ? CDISASM_X86_GROUP_AVX512F_256
                        : CDISASM_X86_GROUP_AVX512F_512));
    }
    if ((name_id == CDISASM_X86_NAME_VCOMPRESSPD
            || name_id == CDISASM_X86_NAME_VCOMPRESSPS
            || name_id == CDISASM_X86_NAME_VEXPANDPD
            || name_id == CDISASM_X86_NAME_VEXPANDPS)
        && decoder->form_id >= UINT16_C(3637)
        && decoder->form_id <= UINT16_C(4538)) {
        unsigned int width_index;

        if (name_id == CDISASM_X86_NAME_VCOMPRESSPD) {
            width_index = (decoder->form_id - UINT16_C(3637)) % 3u;
        } else if (name_id == CDISASM_X86_NAME_VCOMPRESSPS) {
            width_index = (decoder->form_id - UINT16_C(3643)) % 3u;
        } else if (name_id == CDISASM_X86_NAME_VEXPANDPD) {
            width_index = (decoder->form_id - UINT16_C(4527)) / 2u;
        } else {
            width_index = (decoder->form_id - UINT16_C(4533)) / 2u;
        }
        return add_x86_group(
            instruction,
            width_index == 0u ? CDISASM_X86_GROUP_AVX512F_128
                : width_index == 1u ? CDISASM_X86_GROUP_AVX512F_256
                                    : CDISASM_X86_GROUP_AVX512F_512);
    }
    if ((name_id == CDISASM_X86_NAME_VPTERNLOGD
            || name_id == CDISASM_X86_NAME_VPTERNLOGQ)
        && decoder->form_id >= UINT16_C(8259)
        && decoder->form_id <= UINT16_C(8270)) {
        const cdisasm_x86_form_id base =
            name_id == CDISASM_X86_NAME_VPTERNLOGD
                ? UINT16_C(8259) : UINT16_C(8265);
        const unsigned int width_index =
            (decoder->form_id - base) / 2u;

        return add_x86_group(
            instruction,
            width_index == 0u ? CDISASM_X86_GROUP_AVX512F_128
                : width_index == 1u ? CDISASM_X86_GROUP_AVX512F_256
                                    : CDISASM_X86_GROUP_AVX512F_512);
    }
    if (name_id == CDISASM_X86_NAME_VMPSADBW
        && decoder->form_id >= UINT16_C(5989)
        && decoder->form_id <= UINT16_C(5996)) {
        cdisasm_x86_group_id group_id;

        if (decoder->form_id <= UINT16_C(5990)) {
            group_id = CDISASM_X86_GROUP_AVX512_MEDIAX_128;
        } else if (decoder->form_id >= UINT16_C(5993)
            && decoder->form_id <= UINT16_C(5994)) {
            group_id = CDISASM_X86_GROUP_AVX512_MEDIAX_256;
        } else if (decoder->form_id >= UINT16_C(5995)) {
            group_id = CDISASM_X86_GROUP_AVX512_MEDIAX_512;
        } else {
            /* 5991/5992 are the VEX AVX2 forms. */
            return 1;
        }
        return add_x86_group(instruction, group_id);
    }
    if (name_id == CDISASM_X86_NAME_VMULBF16
        && decoder->form_id >= UINT16_C(6006)
        && decoder->form_id <= UINT16_C(6011)) {
        const unsigned int width_index =
            (decoder->form_id - UINT16_C(6006)) / 2u;

        return add_x86_group(
            instruction,
            (cdisasm_x86_group_id)(
                CDISASM_X86_GROUP_AVX10_2_BF16_128 + width_index));
    }
    if (name_id == CDISASM_X86_NAME_VCVTNEPS2BF16
        && decoder->form_id >= UINT16_C(3833)
        && decoder->form_id <= UINT16_C(3842)) {
        cdisasm_x86_group_id width_group;

        if (decoder->form_id == UINT16_C(3833)
            || decoder->form_id == UINT16_C(3835)) {
            width_group = CDISASM_X86_GROUP_AVX512_BF16_128;
        } else if (decoder->form_id == UINT16_C(3834)
            || decoder->form_id == UINT16_C(3836)) {
            width_group = CDISASM_X86_GROUP_AVX512_BF16_256;
        } else if (decoder->form_id == UINT16_C(3841)
            || decoder->form_id == UINT16_C(3842)) {
            width_group = CDISASM_X86_GROUP_AVX512_BF16_512;
        } else {
            /* 3837--3840 are the VEX AVX_NE_CONVERT identities. */
            return 1;
        }
        return add_x86_group(instruction, width_group);
    }
    if (name_id >= CDISASM_X86_NAME_VBROADCASTF32X4
        && name_id <= CDISASM_X86_NAME_VBROADCASTI64X4
        && ((decoder->form_id >= UINT16_C(3548)
                && decoder->form_id <= UINT16_C(3553))
            || (decoder->form_id >= UINT16_C(3561)
                && decoder->form_id <= UINT16_C(3566)))) {
        cdisasm_x86_group_id width_group;

        switch (decoder->form_id) {
            case UINT16_C(3548):
            case UINT16_C(3561):
                width_group = CDISASM_X86_GROUP_AVX512F_256;
                break;
            case UINT16_C(3549):
            case UINT16_C(3553):
            case UINT16_C(3562):
            case UINT16_C(3566):
                width_group = CDISASM_X86_GROUP_AVX512F_512;
                break;
            case UINT16_C(3551):
            case UINT16_C(3564):
                width_group = CDISASM_X86_GROUP_AVX512DQ_256;
                break;
            default:
                width_group = CDISASM_X86_GROUP_AVX512DQ_512;
                break;
        }
        return add_x86_group(instruction, width_group);
    }
    if ((name_id == CDISASM_X86_NAME_VBROADCASTF32X2
            && decoder->form_id >= UINT16_C(3544)
            && decoder->form_id <= UINT16_C(3547))
        || (name_id == CDISASM_X86_NAME_VBROADCASTI32X2
            && decoder->form_id >= UINT16_C(3555)
            && decoder->form_id <= UINT16_C(3560))) {
        unsigned int width_index;

        if (name_id == CDISASM_X86_NAME_VBROADCASTF32X2) {
            width_index = 1u + (decoder->form_id - UINT16_C(3544)) / 2u;
        } else {
            width_index = (decoder->form_id - UINT16_C(3555)) / 2u;
        }
        return add_x86_group(
            instruction,
            width_index == 0u ? CDISASM_X86_GROUP_AVX512DQ_128
                : width_index == 1u ? CDISASM_X86_GROUP_AVX512DQ_256
                                    : CDISASM_X86_GROUP_AVX512DQ_512);
    }
    if ((name_id == CDISASM_X86_NAME_VEXTRACTF32X8
            && decoder->form_id >= UINT16_C(4545)
            && decoder->form_id <= UINT16_C(4546))
        || (name_id == CDISASM_X86_NAME_VEXTRACTI32X8
            && decoder->form_id >= UINT16_C(4559)
            && decoder->form_id <= UINT16_C(4560))) {
        return add_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512DQ_512);
    }
    if ((name_id == CDISASM_X86_NAME_VEXTRACTF64X4
            && decoder->form_id >= UINT16_C(4551)
            && decoder->form_id <= UINT16_C(4552))
        || (name_id == CDISASM_X86_NAME_VEXTRACTI64X4
            && decoder->form_id >= UINT16_C(4565)
            && decoder->form_id <= UINT16_C(4566))) {
        return add_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F_512);
    }
    if ((name_id == CDISASM_X86_NAME_VEXTRACTF32X4
            && decoder->form_id >= UINT16_C(4541)
            && decoder->form_id <= UINT16_C(4544))
        || (name_id == CDISASM_X86_NAME_VEXTRACTI32X4
            && decoder->form_id >= UINT16_C(4555)
            && decoder->form_id <= UINT16_C(4558))) {
        const cdisasm_x86_form_id base = name_id
                == CDISASM_X86_NAME_VEXTRACTF32X4
            ? UINT16_C(4541) : UINT16_C(4555);
        const unsigned int width_index =
            (decoder->form_id - base) % 2u;

        return add_x86_group(
            instruction,
            width_index == 0u ? CDISASM_X86_GROUP_AVX512F_256
                              : CDISASM_X86_GROUP_AVX512F_512);
    }
    if ((name_id == CDISASM_X86_NAME_VEXTRACTF64X2
            && decoder->form_id >= UINT16_C(4547)
            && decoder->form_id <= UINT16_C(4550))
        || (name_id == CDISASM_X86_NAME_VEXTRACTI64X2
            && decoder->form_id >= UINT16_C(4561)
            && decoder->form_id <= UINT16_C(4564))) {
        const cdisasm_x86_form_id base = name_id
                == CDISASM_X86_NAME_VEXTRACTF64X2
            ? UINT16_C(4547) : UINT16_C(4561);
        const unsigned int width_index =
            (decoder->form_id - base) % 2u;

        return add_x86_group(
            instruction,
            width_index == 0u ? CDISASM_X86_GROUP_AVX512DQ_256
                              : CDISASM_X86_GROUP_AVX512DQ_512);
    }
    if (name_id == CDISASM_X86_NAME_VMULPH
        && decoder->form_id >= UINT16_C(6022)
        && decoder->form_id <= UINT16_C(6027)) {
        cdisasm_x86_group_id width_group;

        if (decoder->form_id <= UINT16_C(6023)) {
            width_group = CDISASM_X86_GROUP_AVX512_FP16_128;
        } else if (decoder->form_id <= UINT16_C(6025)) {
            width_group = CDISASM_X86_GROUP_AVX512_FP16_256;
        } else {
            width_group = CDISASM_X86_GROUP_AVX512_FP16_512;
        }
        return add_x86_group(instruction, width_group);
    }
    if (name_id == CDISASM_X86_NAME_VMULSH
        && decoder->form_id >= UINT16_C(6042)
        && decoder->form_id <= UINT16_C(6043)) {
        return add_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512_FP16_SCALAR);
    }
    if ((name_id == CDISASM_X86_NAME_VORPD
            && ((decoder->form_id >= UINT16_C(6056)
                    && decoder->form_id <= UINT16_C(6057))
                || (decoder->form_id >= UINT16_C(6060)
                    && decoder->form_id <= UINT16_C(6063))))
        || (name_id == CDISASM_X86_NAME_VORPS
            && ((decoder->form_id >= UINT16_C(6066)
                    && decoder->form_id <= UINT16_C(6067))
                || (decoder->form_id >= UINT16_C(6070)
                    && decoder->form_id <= UINT16_C(6073))))) {
        cdisasm_x86_group_id width_group;

        if (decoder->form_id == UINT16_C(6056)
            || decoder->form_id == UINT16_C(6057)
            || decoder->form_id == UINT16_C(6066)
            || decoder->form_id == UINT16_C(6067)) {
            width_group = CDISASM_X86_GROUP_AVX512DQ_128;
        } else if (decoder->form_id == UINT16_C(6060)
            || decoder->form_id == UINT16_C(6061)
            || decoder->form_id == UINT16_C(6070)
            || decoder->form_id == UINT16_C(6071)) {
            width_group = CDISASM_X86_GROUP_AVX512DQ_256;
        } else {
            width_group = CDISASM_X86_GROUP_AVX512DQ_512;
        }
        return add_x86_group(instruction, width_group);
    }
    if ((name_id == CDISASM_X86_NAME_VP2INTERSECTD
            && decoder->form_id >= UINT16_C(6074)
            && decoder->form_id <= UINT16_C(6079))
        || (name_id == CDISASM_X86_NAME_VP2INTERSECTQ
            && decoder->form_id >= UINT16_C(6080)
            && decoder->form_id <= UINT16_C(6085))) {
        const cdisasm_x86_form_id base =
            name_id == CDISASM_X86_NAME_VP2INTERSECTD
                ? UINT16_C(6074) : UINT16_C(6080);
        const unsigned int width_index =
            (decoder->form_id - base) / 2u;

        return add_x86_group(
            instruction,
            (cdisasm_x86_group_id)(
                CDISASM_X86_GROUP_AVX512_VP2INTERSECT_128
                + width_index));
    }
    if ((name_id == CDISASM_X86_NAME_VPABSB
            && ((decoder->form_id >= UINT16_C(6090)
                    && decoder->form_id <= UINT16_C(6093))
                || (decoder->form_id >= UINT16_C(6096)
                    && decoder->form_id <= UINT16_C(6097))))
        || (name_id == CDISASM_X86_NAME_VPABSW
            && ((decoder->form_id >= UINT16_C(6116)
                    && decoder->form_id <= UINT16_C(6119))
                || (decoder->form_id >= UINT16_C(6122)
                    && decoder->form_id <= UINT16_C(6123))))) {
        const cdisasm_x86_form_id base =
            name_id == CDISASM_X86_NAME_VPABSB
                ? UINT16_C(6090) : UINT16_C(6116);
        const unsigned int relative = decoder->form_id - base;
        const unsigned int width_index = relative < 4u
            ? relative / 2u : 2u;

        return add_x86_group(
            instruction,
            (cdisasm_x86_group_id)(
                CDISASM_X86_GROUP_AVX512BW_128 +
                (width_index == 0u ? 0u : width_index + 1u)));
    }
    if ((name_id == CDISASM_X86_NAME_VPABSD
            && ((decoder->form_id >= UINT16_C(6100)
                    && decoder->form_id <= UINT16_C(6103))
                || (decoder->form_id >= UINT16_C(6106)
                    && decoder->form_id <= UINT16_C(6107))))
        || (name_id == CDISASM_X86_NAME_VPABSQ
            && decoder->form_id >= UINT16_C(6108)
            && decoder->form_id <= UINT16_C(6113))) {
        cdisasm_x86_form_id base;
        unsigned int relative;
        unsigned int width_index;

        base = name_id == CDISASM_X86_NAME_VPABSD
            ? UINT16_C(6100) : UINT16_C(6108);
        relative = decoder->form_id - base;
        width_index = name_id == CDISASM_X86_NAME_VPABSD
                && relative >= 6u
            ? 2u : relative / 2u;
        return add_x86_group(
            instruction,
            width_index == 0u ? CDISASM_X86_GROUP_AVX512F_128
                : width_index == 1u ? CDISASM_X86_GROUP_AVX512F_256
                                    : CDISASM_X86_GROUP_AVX512F_512);
    }
    if ((name_id == CDISASM_X86_NAME_VPACKSSDW
            && ((decoder->form_id >= UINT16_C(6126)
                    && decoder->form_id <= UINT16_C(6129))
                || (decoder->form_id >= UINT16_C(6132)
                    && decoder->form_id <= UINT16_C(6133))))
        || (name_id == CDISASM_X86_NAME_VPACKSSWB
            && ((decoder->form_id >= UINT16_C(6136)
                    && decoder->form_id <= UINT16_C(6139))
                || (decoder->form_id >= UINT16_C(6142)
                    && decoder->form_id <= UINT16_C(6143))))
        || (name_id == CDISASM_X86_NAME_VPACKUSDW
            && ((decoder->form_id >= UINT16_C(6146)
                    && decoder->form_id <= UINT16_C(6147))
                || (decoder->form_id >= UINT16_C(6150)
                    && decoder->form_id <= UINT16_C(6153))))
        || (name_id == CDISASM_X86_NAME_VPACKUSWB
            && ((decoder->form_id >= UINT16_C(6156)
                    && decoder->form_id <= UINT16_C(6157))
                || (decoder->form_id >= UINT16_C(6160)
                    && decoder->form_id <= UINT16_C(6163))))) {
        cdisasm_x86_form_id base;
        unsigned int relative;
        unsigned int width_index;

        if (name_id == CDISASM_X86_NAME_VPACKSSDW) {
            base = UINT16_C(6126);
        } else if (name_id == CDISASM_X86_NAME_VPACKSSWB) {
            base = UINT16_C(6136);
        } else if (name_id == CDISASM_X86_NAME_VPACKUSDW) {
            base = UINT16_C(6146);
        } else {
            base = UINT16_C(6156);
        }
        relative = decoder->form_id - base;
        if (name_id == CDISASM_X86_NAME_VPACKSSDW
            || name_id == CDISASM_X86_NAME_VPACKSSWB) {
            width_index = relative < 4u ? relative / 2u : 2u;
        } else {
            width_index = relative < 2u ? 0u
                : relative < 6u ? 1u : 2u;
        }
        return add_x86_group(
            instruction,
            width_index == 0u ? CDISASM_X86_GROUP_AVX512BW_128
                : width_index == 1u ? CDISASM_X86_GROUP_AVX512BW_256
                                    : CDISASM_X86_GROUP_AVX512BW_512);
    }
    if ((name_id == CDISASM_X86_NAME_VMULPD
            && ((decoder->form_id >= UINT16_C(6014)
                    && decoder->form_id <= UINT16_C(6017))
                || (decoder->form_id >= UINT16_C(6020)
                    && decoder->form_id <= UINT16_C(6021))))
        || (name_id == CDISASM_X86_NAME_VMULPS
            && ((decoder->form_id >= UINT16_C(6030)
                    && decoder->form_id <= UINT16_C(6033))
                || (decoder->form_id >= UINT16_C(6036)
                    && decoder->form_id <= UINT16_C(6037))))) {
        cdisasm_x86_group_id width_group;

        if (decoder->form_id == UINT16_C(6014)
            || decoder->form_id == UINT16_C(6015)
            || decoder->form_id == UINT16_C(6030)
            || decoder->form_id == UINT16_C(6031)) {
            width_group = CDISASM_X86_GROUP_AVX512F_128;
        } else if (decoder->form_id == UINT16_C(6016)
            || decoder->form_id == UINT16_C(6017)
            || decoder->form_id == UINT16_C(6032)
            || decoder->form_id == UINT16_C(6033)) {
            width_group = CDISASM_X86_GROUP_AVX512F_256;
        } else {
            width_group = CDISASM_X86_GROUP_AVX512F_512;
        }
        return add_x86_group(instruction, width_group);
    }
    if ((name_id == CDISASM_X86_NAME_VMULSD
            && decoder->form_id >= UINT16_C(6040)
            && decoder->form_id <= UINT16_C(6041))
        || (name_id == CDISASM_X86_NAME_VMULSS
            && decoder->form_id >= UINT16_C(6046)
            && decoder->form_id <= UINT16_C(6047))) {
        return add_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F_SCALAR);
    }
    if ((name_id == CDISASM_X86_NAME_VMOVUPD
            && decoder->form_id >= UINT16_C(5947)
            && decoder->form_id <= UINT16_C(5962))
        || (name_id == CDISASM_X86_NAME_VMOVUPS
            && decoder->form_id >= UINT16_C(5964)
            && decoder->form_id <= UINT16_C(5979))) {
        const cdisasm_x86_form_id base =
            name_id == CDISASM_X86_NAME_VMOVUPS
                ? UINT16_C(5963) : UINT16_C(5946);
        const unsigned int relative = decoder->form_id - base;
        cdisasm_x86_group_id width_group;

        if (relative == 1u || relative == 8u || relative == 9u) {
            width_group = CDISASM_X86_GROUP_AVX512F_128;
        } else if (relative == 2u || relative == 10u
            || relative == 11u) {
            width_group = CDISASM_X86_GROUP_AVX512F_256;
        } else if (relative == 3u || relative == 15u
            || relative == 16u) {
            width_group = CDISASM_X86_GROUP_AVX512F_512;
        } else {
            /* The remaining identities in these contiguous ranges are the
             * AVX VEX forms and carry no exact AVX512F width group. */
            return 1;
        }
        return add_x86_group(instruction, width_group);
    }
    if ((name_id == CDISASM_X86_NAME_VMOVSD
            && (decoder->form_id == UINT16_C(5909)
                || decoder->form_id == UINT16_C(5914)
                || decoder->form_id == UINT16_C(5915)))
        || (name_id == CDISASM_X86_NAME_VMOVSS
            && (decoder->form_id == UINT16_C(5940)
                || decoder->form_id == UINT16_C(5944)
                || decoder->form_id == UINT16_C(5945)))) {
        /* This exact ISA_SET lies beyond the two compact decoder capability
         * words.  Structural admission uses the pinned profile predicate;
         * publish its stable group here for exact runtime-bit selection. */
        return add_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F_SCALAR);
    }
    if ((name_id == CDISASM_X86_NAME_MOVSD
            || name_id == CDISASM_X86_NAME_CMPSD)
        && (decoder->required_caps
            & (X86_CAP_SSE | X86_CAP_SSE2 | X86_CAP_SSE3
                | X86_CAP_SSSE3 | X86_CAP_SSE41 | X86_CAP_SSE4A
                | X86_CAP_SSE42)) != 0) {
        return 1;
    }
    switch (name_id) {
        case CDISASM_X86_NAME_AESDEC128KL:
        case CDISASM_X86_NAME_AESDEC256KL:
        case CDISASM_X86_NAME_AESENC128KL:
        case CDISASM_X86_NAME_AESENC256KL:
        case CDISASM_X86_NAME_ENCODEKEY128:
        case CDISASM_X86_NAME_ENCODEKEY256:
        case CDISASM_X86_NAME_LOADIWKEY:
            return add_x86_group(
                instruction, CDISASM_X86_GROUP_KEYLOCKER);

        case CDISASM_X86_NAME_AESDECWIDE128KL:
        case CDISASM_X86_NAME_AESDECWIDE256KL:
        case CDISASM_X86_NAME_AESENCWIDE128KL:
        case CDISASM_X86_NAME_AESENCWIDE256KL:
            return add_x86_group(
                instruction, CDISASM_X86_GROUP_KEYLOCKER_WIDE);

        case CDISASM_X86_NAME_HRESET:
            return add_x86_group(instruction, CDISASM_X86_GROUP_HRESET);

        case CDISASM_X86_NAME_CLDEMOTE:
            return add_x86_group(instruction, CDISASM_X86_GROUP_CLDEMOTE);

        case CDISASM_X86_NAME_CLZERO:
            return add_x86_group(instruction, CDISASM_X86_GROUP_CLZERO);

        case CDISASM_X86_NAME_PCONFIG:
            return add_x86_group(instruction, CDISASM_X86_GROUP_PCONFIG);

        case CDISASM_X86_NAME_PBNDKB:
            return add_x86_group(instruction, CDISASM_X86_GROUP_PBNDKB);

        case CDISASM_X86_NAME_RDPRU:
            return add_x86_group(instruction, CDISASM_X86_GROUP_RDPRU);

        case CDISASM_X86_NAME_PTWRITE:
            return add_x86_group(instruction, CDISASM_X86_GROUP_PTWRITE);

        case CDISASM_X86_NAME_CLAC:
        case CDISASM_X86_NAME_STAC:
            return add_x86_group(instruction, CDISASM_X86_GROUP_SMAP);

        case CDISASM_X86_NAME_PREFETCHRST2:
            return add_x86_group(instruction, CDISASM_X86_GROUP_MOVRS);

        case CDISASM_X86_NAME_PREFETCHWT1:
            return add_x86_group(
                instruction, CDISASM_X86_GROUP_PREFETCHWT1);

        case CDISASM_X86_NAME_PREFETCHIT0:
        case CDISASM_X86_NAME_PREFETCHIT1:
            return add_x86_group(
                instruction, CDISASM_X86_GROUP_ICACHE_PREFETCH);

        case CDISASM_X86_NAME_MCOMMIT:
            return add_x86_group(instruction, CDISASM_X86_GROUP_MCOMMIT);

        case CDISASM_X86_NAME_MONITORX:
        case CDISASM_X86_NAME_MWAITX:
            return add_x86_group(instruction, CDISASM_X86_GROUP_MONITORX);

        case CDISASM_X86_NAME_INVLPGB:
        case CDISASM_X86_NAME_TLBSYNC:
            return add_x86_group(
                instruction, CDISASM_X86_GROUP_AMD_INVLPGB);

        case CDISASM_X86_NAME_PSMASH:
        case CDISASM_X86_NAME_PVALIDATE:
        case CDISASM_X86_NAME_RMPADJUST:
        case CDISASM_X86_NAME_RMPUPDATE:
            return add_x86_group(instruction, CDISASM_X86_GROUP_SNP);

        case CDISASM_X86_NAME_FCMOVB:
        case CDISASM_X86_NAME_FCMOVBE:
        case CDISASM_X86_NAME_FCMOVE:
        case CDISASM_X86_NAME_FCMOVNB:
        case CDISASM_X86_NAME_FCMOVNBE:
        case CDISASM_X86_NAME_FCMOVNE:
        case CDISASM_X86_NAME_FCMOVNU:
        case CDISASM_X86_NAME_FCMOVU:
            return add_x86_group(instruction, CDISASM_X86_GROUP_FCMOV);

        case CDISASM_X86_NAME_FCOMI:
        case CDISASM_X86_NAME_FCOMIP:
        case CDISASM_X86_NAME_FUCOMI:
        case CDISASM_X86_NAME_FUCOMIP:
            return add_x86_group(instruction, CDISASM_X86_GROUP_FCOMI);

        case CDISASM_X86_NAME_LAHF:
        case CDISASM_X86_NAME_SAHF:
            return add_x86_group(instruction, CDISASM_X86_GROUP_LAHF);

        case CDISASM_X86_NAME_CMPSB:
        case CDISASM_X86_NAME_CMPSW:
        case CDISASM_X86_NAME_LODSB:
        case CDISASM_X86_NAME_LODSW:
        case CDISASM_X86_NAME_STOSB:
        case CDISASM_X86_NAME_STOSW:
        case CDISASM_X86_NAME_SCASB:
        case CDISASM_X86_NAME_SCASW:
        case CDISASM_X86_NAME_MOVSB:
        case CDISASM_X86_NAME_MOVSW:
        case CDISASM_X86_NAME_POPF:
        case CDISASM_X86_NAME_PUSHF:
        case CDISASM_X86_NAME_LOOP:
        case CDISASM_X86_NAME_LOOPE:
        case CDISASM_X86_NAME_LOOPNE:
        case CDISASM_X86_NAME_IN:
        case CDISASM_X86_NAME_OUT:
        case CDISASM_X86_NAME_XCHG:
        case CDISASM_X86_NAME_HLT:
        case CDISASM_X86_NAME_CLI:
        case CDISASM_X86_NAME_STI:
            return add_x86_group(instruction, CDISASM_X86_GROUP_I86);

        case CDISASM_X86_NAME_CLTS:
            return add_x86_group(
                instruction, CDISASM_X86_GROUP_I286REAL);

        case CDISASM_X86_NAME_INVD:
            return add_x86_group(
                instruction, CDISASM_X86_GROUP_I486REAL);

        case CDISASM_X86_NAME_EMMS:
            return add_x86_group(
                instruction, CDISASM_X86_GROUP_PENTIUMMMX);

        case CDISASM_X86_NAME_CDQ:
        case CDISASM_X86_NAME_CWDE:
        case CDISASM_X86_NAME_CMPSD:
        case CDISASM_X86_NAME_INSD:
        case CDISASM_X86_NAME_IRETD:
        case CDISASM_X86_NAME_JCXZ:
        case CDISASM_X86_NAME_JECXZ:
        case CDISASM_X86_NAME_LODSD:
        case CDISASM_X86_NAME_MOVSD:
        case CDISASM_X86_NAME_OUTSD:
        case CDISASM_X86_NAME_POPAD:
        case CDISASM_X86_NAME_POPFD:
        case CDISASM_X86_NAME_PUSHAD:
        case CDISASM_X86_NAME_PUSHFD:
        case CDISASM_X86_NAME_SCASD:
        case CDISASM_X86_NAME_STOSD:
            return add_x86_group(instruction, CDISASM_X86_GROUP_I386);

        case CDISASM_X86_NAME_CDQE:
        case CDISASM_X86_NAME_CQO:
        case CDISASM_X86_NAME_CMPSQ:
        case CDISASM_X86_NAME_ENDBR64:
        case CDISASM_X86_NAME_IRETQ:
        case CDISASM_X86_NAME_JRCXZ:
        case CDISASM_X86_NAME_LODSQ:
        case CDISASM_X86_NAME_MOVABS:
        case CDISASM_X86_NAME_MOVSQ:
        case CDISASM_X86_NAME_MOVSXD:
        case CDISASM_X86_NAME_POPFQ:
        case CDISASM_X86_NAME_PUSHFQ:
        case CDISASM_X86_NAME_SCASQ:
        case CDISASM_X86_NAME_STOSQ:
            return add_x86_group(instruction, CDISASM_X86_GROUP_AMD64);

        default:
            return 1;
    }
}

static int add_required_cap_groups(
    const x86_decoder *decoder,
    cdisasm_instruction *instruction)
{
    uint64_t caps = decoder->required_caps;
    unsigned int condition;

#define ADD_CAP_GROUP(capability, group_id) \
    do { \
        if ((caps & (capability)) != 0 \
            && !add_x86_group(instruction, (group_id))) { \
            return 0; \
        } \
    } while (0)

    ADD_CAP_GROUP(X86_CAP_80186, CDISASM_X86_GROUP_I186);
    ADD_CAP_GROUP(X86_CAP_80286, CDISASM_X86_GROUP_I286);
    ADD_CAP_GROUP(X86_CAP_80386, CDISASM_X86_GROUP_I386);
    ADD_CAP_GROUP(X86_CAP_80486, CDISASM_X86_GROUP_I486);
    ADD_CAP_GROUP(X86_CAP_CPUID, CDISASM_X86_GROUP_CPUID);
    ADD_CAP_GROUP(X86_CAP_PENTIUM, CDISASM_X86_GROUP_PENTIUM);
    ADD_CAP_GROUP(X86_CAP_P6, CDISASM_X86_GROUP_P6);
    ADD_CAP_GROUP(X86_CAP_MMX, CDISASM_X86_GROUP_MMX);
    ADD_CAP_GROUP(X86_CAP_SEP, CDISASM_X86_GROUP_SEP);
    if ((caps & X86_CAP_PAUSE) != 0) {
        if (!add_x86_group(instruction, CDISASM_X86_GROUP_SSE2)
            || !add_x86_group(instruction, CDISASM_X86_GROUP_PAUSE)) {
            return 0;
        }
    }
    ADD_CAP_GROUP(X86_CAP_AMD64, CDISASM_X86_GROUP_AMD64);
    ADD_CAP_GROUP(X86_CAP_SMX, CDISASM_X86_GROUP_SMX);
    ADD_CAP_GROUP(X86_CAP_POPCNT, CDISASM_X86_GROUP_POPCNT);
    ADD_CAP_GROUP(X86_CAP_LZCNT, CDISASM_X86_GROUP_LZCNT);
    ADD_CAP_GROUP(X86_CAP_BMI1, CDISASM_X86_GROUP_BMI1);
    ADD_CAP_GROUP(X86_CAP_CET_IBT, CDISASM_X86_GROUP_CET_IBT);
    ADD_CAP_GROUP(X86_CAP_VMX, CDISASM_X86_GROUP_VMX);
    ADD_CAP_GROUP(X86_CAP_INVEPT, CDISASM_X86_GROUP_VMX);
    ADD_CAP_GROUP(X86_CAP_INVVPID, CDISASM_X86_GROUP_VMX);
    ADD_CAP_GROUP(X86_CAP_VMFUNC, CDISASM_X86_GROUP_VMX);
    ADD_CAP_GROUP(X86_CAP_SVM, CDISASM_X86_GROUP_SVM);
    ADD_CAP_GROUP(X86_CAP_SEV_ES, CDISASM_X86_GROUP_SVM);
    ADD_CAP_GROUP(X86_CAP_3DNOW, CDISASM_X86_GROUP_3DNOW);
    ADD_CAP_GROUP(X86_CAP_3DNOW_EXT, CDISASM_X86_GROUP_3DNOW_EXT);
    ADD_CAP_GROUP(X86_CAP_PREFETCH, CDISASM_X86_GROUP_PREFETCHW);
    ADD_CAP_GROUP(X86_CAP_PREFETCHW, CDISASM_X86_GROUP_PREFETCHW);
    ADD_CAP_GROUP(X86_CAP_UD0, CDISASM_X86_GROUP_P6);
    ADD_CAP_GROUP(X86_CAP_UD1, CDISASM_X86_GROUP_P6);
    ADD_CAP_GROUP(X86_CAP_HLE, CDISASM_X86_GROUP_HLE);
    ADD_CAP_GROUP(X86_CAP_AVX, CDISASM_X86_GROUP_AVX);
    ADD_CAP_GROUP(X86_CAP_AVX2, CDISASM_X86_GROUP_AVX2);
    ADD_CAP_GROUP(X86_CAP_SSE, CDISASM_X86_GROUP_SSE);
    ADD_CAP_GROUP(X86_CAP_SSE2, CDISASM_X86_GROUP_SSE2);
    ADD_CAP_GROUP(X86_CAP_SSE3, CDISASM_X86_GROUP_SSE3);
    ADD_CAP_GROUP(X86_CAP_SSSE3, CDISASM_X86_GROUP_SSSE3);
    ADD_CAP_GROUP(X86_CAP_SSE41, CDISASM_X86_GROUP_SSE41);
    ADD_CAP_GROUP(X86_CAP_SSE4A, CDISASM_X86_GROUP_SSE4A);
    ADD_CAP_GROUP(X86_CAP_SSE42, CDISASM_X86_GROUP_SSE42);
    ADD_CAP_GROUP(X86_CAP_X87, CDISASM_X86_GROUP_X87);
    ADD_CAP_GROUP(X86_CAP_CLFLUSH, CDISASM_X86_GROUP_CLFLUSH);
    ADD_CAP_GROUP(X86_CAP_CLFLUSHOPT, CDISASM_X86_GROUP_CLFLUSHOPT);
    ADD_CAP_GROUP(X86_CAP_CLWB, CDISASM_X86_GROUP_CLWB);
    ADD_CAP_GROUP(X86_CAP_RDPID, CDISASM_X86_GROUP_RDPID);
    ADD_CAP_GROUP(X86_CAP_SERIALIZE, CDISASM_X86_GROUP_SERIALIZE);
    ADD_CAP_GROUP(X86_CAP_MOVDIRI, CDISASM_X86_GROUP_MOVDIRI);
    ADD_CAP_GROUP(X86_CAP_MOVDIR64B, CDISASM_X86_GROUP_MOVDIR64B);
    ADD_CAP_GROUP(X86_CAP_WBNOINVD, CDISASM_X86_GROUP_WBNOINVD);
    ADD_CAP_GROUP(X86_CAP_FXSR, CDISASM_X86_GROUP_FXSR);
    ADD_CAP_GROUP(X86_CAP_MONITOR, CDISASM_X86_GROUP_MONITOR_MWAIT);
    ADD_CAP_GROUP(X86_CAP_RDTSCP, CDISASM_X86_GROUP_RDTSCP);
    ADD_CAP_GROUP(X86_CAP_CMPXCHG16B, CDISASM_X86_GROUP_CMPXCHG16B);

#undef ADD_CAP_GROUP

    for (condition = 0u; condition < 16u; ++condition) {
        if ((decoder->name_id == move_condition_name[condition]
                || decoder->name_id == apx_move_condition_name[condition])
            && !add_x86_group(instruction, CDISASM_X86_GROUP_CMOV)) {
            return 0;
        }
    }
    return 1;
}

static int add_effective_encoding_groups(
    const x86_decoder *decoder,
    cdisasm_instruction *instruction)
{
    unsigned int index;

    if (!add_required_cap_groups(decoder, instruction)
        || !add_name_form_groups(decoder, instruction, decoder->name_id)) {
        return 0;
    }
    if (decoder->rex_present
        && !add_x86_group(instruction, CDISASM_X86_GROUP_AMD64)) {
        return 0;
    }
    for (index = 0; index < decoder->operand_count; ++index) {
        const x86_operand *operand = &decoder->operand[index];

        if (!add_register_form_groups(instruction, operand->reg)
            || !add_register_form_groups(instruction, operand->base_reg)
            || !add_register_form_groups(instruction, operand->index_reg)
            || !add_register_form_groups(instruction, operand->segment_reg)) {
            return 0;
        }
    }
#if USE_EXTRA_OPCODES
    if (decoder->name_id == CDISASM_X86_NAME_TDCALL
        || decoder->name_id == CDISASM_X86_NAME_SEAMRET
        || decoder->name_id == CDISASM_X86_NAME_SEAMOPS
        || decoder->name_id == CDISASM_X86_NAME_SEAMCALL) {
        if (!add_x86_group(instruction, CDISASM_X86_GROUP_TDX)) {
            return 0;
        }
    }
    if (decoder->name_id == CDISASM_X86_NAME_REP_MONTMUL
        && !add_x86_group(
            instruction, CDISASM_X86_GROUP_VIA_PADLOCK_MONTMUL)) {
        return 0;
    }
    if ((decoder->name_id == CDISASM_X86_NAME_REP_XCRYPTCBC
            || decoder->name_id == CDISASM_X86_NAME_REP_XCRYPTCFB
            || decoder->name_id == CDISASM_X86_NAME_REP_XCRYPTCTR
            || decoder->name_id == CDISASM_X86_NAME_REP_XCRYPTECB
            || decoder->name_id == CDISASM_X86_NAME_REP_XCRYPTOFB)
        && !add_x86_group(
            instruction, CDISASM_X86_GROUP_VIA_PADLOCK_AES)) {
        return 0;
    }
    if ((decoder->name_id == CDISASM_X86_NAME_REP_XSHA1
            || decoder->name_id == CDISASM_X86_NAME_REP_XSHA256)
        && !add_x86_group(
            instruction, CDISASM_X86_GROUP_VIA_PADLOCK_SHA)) {
        return 0;
    }
    if (decoder->name_id == CDISASM_X86_NAME_REP_XSTORE
        || decoder->name_id == CDISASM_X86_NAME_XSTORE) {
        if (!add_x86_group(
                instruction, CDISASM_X86_GROUP_VIA_PADLOCK_RNG)) {
            return 0;
        }
    }
    if (decoder->used_avx_ne_convert
        && !add_x86_group(
            instruction, CDISASM_X86_GROUP_AVX_NE_CONVERT)) {
        return 0;
    }
    {
        cdisasm_x86_group_id group_id;

        for (group_id = X86_EXTRA_GROUP_BASE;
             group_id <= X86_EXTRA_GROUP_LAST;
             ++group_id) {
            const int high = group_id >= X86_EXTRA_GROUP_HIGH_BASE;
            const uint64_t bit = high
                ? X86_EXTRA_CAP_HIGH(group_id)
                : X86_EXTRA_CAP(group_id);
            const uint64_t used = high
                ? decoder->used_extra_groups_high
                : decoder->used_extra_groups;

            if ((used & bit) != 0
                && !add_x86_group(instruction, group_id)) {
                return 0;
            }
        }
    }
    if (decoder->used_rao_int
        && !add_x86_group(instruction, CDISASM_X86_GROUP_RAO_INT)) {
        return 0;
    }
    if (decoder->used_user_msr
        && !add_x86_group(instruction, CDISASM_X86_GROUP_USER_MSR)) {
        return 0;
    }
    if (decoder->used_msrlist
        && !add_x86_group(instruction, CDISASM_X86_GROUP_MSRLIST)) {
        return 0;
    }
    if (decoder->used_msr_imm
        && !add_x86_group(instruction, CDISASM_X86_GROUP_MSR_IMM)) {
        return 0;
    }
    if (decoder->used_wrmsrns
        && !add_x86_group(instruction, CDISASM_X86_GROUP_WRMSRNS)) {
        return 0;
    }
#endif
    if (instruction->x86_group_count == 0) {
        return add_x86_group(instruction, CDISASM_X86_GROUP_I86);
    }
    return 1;
}

static cdisasm_operand_access decoded_operand_access(
    const x86_decoder *decoder,
    unsigned int operand_index)
{
    cdisasm_x86_name_id name_id = decoder->name_id;
    uint64_t simd_caps = X86_CAP_SSE | X86_CAP_SSE2 | X86_CAP_SSE3
        | X86_CAP_SSSE3 | X86_CAP_SSE41 | X86_CAP_SSE4A | X86_CAP_SSE42;

    if (operand_index >= decoder->operand_count) {
        return CDISASM_OPERAND_ACCESS_NONE;
    }
    if (decoder->operand[operand_index].access
        != CDISASM_OPERAND_ACCESS_NONE) {
        return (cdisasm_operand_access)
            decoder->operand[operand_index].access;
    }
    if (decoder->operand[operand_index].type == CDISASM_OPERAND_IMMEDIATE) {
        return CDISASM_OPERAND_ACCESS_READ;
    }
    if ((decoder->required_caps & simd_caps) != 0) {
        switch (name_id) {
            case CDISASM_X86_NAME_UCOMISS:
            case CDISASM_X86_NAME_COMISS:
            case CDISASM_X86_NAME_UCOMISD:
            case CDISASM_X86_NAME_COMISD:
            case CDISASM_X86_NAME_PTEST:
            case CDISASM_X86_NAME_PCMPESTRM:
            case CDISASM_X86_NAME_PCMPESTRI:
            case CDISASM_X86_NAME_PCMPISTRM:
            case CDISASM_X86_NAME_PCMPISTRI:
            case CDISASM_X86_NAME_MASKMOVQ:
            case CDISASM_X86_NAME_LDMXCSR:
            case CDISASM_X86_NAME_PREFETCHNTA:
            case CDISASM_X86_NAME_PREFETCHT0:
            case CDISASM_X86_NAME_PREFETCHT1:
            case CDISASM_X86_NAME_PREFETCHT2:
                return CDISASM_OPERAND_ACCESS_READ;

            case CDISASM_X86_NAME_STMXCSR:
            case CDISASM_X86_NAME_MOVUPS:
            case CDISASM_X86_NAME_MOVAPS:
            case CDISASM_X86_NAME_MOVNTPS:
            case CDISASM_X86_NAME_MOVMSKPS:
            case CDISASM_X86_NAME_SQRTPS:
            case CDISASM_X86_NAME_RSQRTPS:
            case CDISASM_X86_NAME_RCPPS:
            case CDISASM_X86_NAME_CVTPS2PI:
            case CDISASM_X86_NAME_CVTTPS2PI:
            case CDISASM_X86_NAME_CVTSS2SI:
            case CDISASM_X86_NAME_CVTTSS2SI:
            case CDISASM_X86_NAME_PEXTRW:
            case CDISASM_X86_NAME_PMOVMSKB:
            case CDISASM_X86_NAME_PSHUFW:
            case CDISASM_X86_NAME_MOVNTQ:
            case CDISASM_X86_NAME_MOVUPD:
            case CDISASM_X86_NAME_MOVAPD:
            case CDISASM_X86_NAME_MOVNTPD:
            case CDISASM_X86_NAME_MOVMSKPD:
            case CDISASM_X86_NAME_SQRTPD:
            case CDISASM_X86_NAME_MOVDQA:
            case CDISASM_X86_NAME_MOVDQU:
            case CDISASM_X86_NAME_CVTPS2PD:
            case CDISASM_X86_NAME_CVTPD2PS:
            case CDISASM_X86_NAME_CVTDQ2PS:
            case CDISASM_X86_NAME_CVTPS2DQ:
            case CDISASM_X86_NAME_CVTTPS2DQ:
            case CDISASM_X86_NAME_CVTSD2SI:
            case CDISASM_X86_NAME_CVTTSD2SI:
            case CDISASM_X86_NAME_MOVDDUP:
            case CDISASM_X86_NAME_MOVSLDUP:
            case CDISASM_X86_NAME_MOVSHDUP:
            case CDISASM_X86_NAME_LDDQU:
            case CDISASM_X86_NAME_PABSB:
            case CDISASM_X86_NAME_PABSW:
            case CDISASM_X86_NAME_PABSD:
            case CDISASM_X86_NAME_PMOVSXBW:
            case CDISASM_X86_NAME_PMOVSXBD:
            case CDISASM_X86_NAME_PMOVSXBQ:
            case CDISASM_X86_NAME_PMOVSXWD:
            case CDISASM_X86_NAME_PMOVSXWQ:
            case CDISASM_X86_NAME_PMOVSXDQ:
            case CDISASM_X86_NAME_MOVNTDQA:
            case CDISASM_X86_NAME_PMOVZXBW:
            case CDISASM_X86_NAME_PMOVZXBD:
            case CDISASM_X86_NAME_PMOVZXBQ:
            case CDISASM_X86_NAME_PMOVZXWD:
            case CDISASM_X86_NAME_PMOVZXWQ:
            case CDISASM_X86_NAME_PMOVZXDQ:
            case CDISASM_X86_NAME_ROUNDPS:
            case CDISASM_X86_NAME_ROUNDPD:
            case CDISASM_X86_NAME_PEXTRB:
            case CDISASM_X86_NAME_PEXTRD:
            case CDISASM_X86_NAME_EXTRACTPS:
            case CDISASM_X86_NAME_MOVNTSS:
            case CDISASM_X86_NAME_MOVNTSD:
                return operand_index == 0
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ;

            case CDISASM_X86_NAME_CRC32:
                return operand_index == 0
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_READ;

            case CDISASM_X86_NAME_MOVSS:
            case CDISASM_X86_NAME_MOVSD:
                if (operand_index != 0) {
                    return CDISASM_OPERAND_ACCESS_READ;
                }
                return decoder->operand[0].type == CDISASM_OPERAND_MEMORY
                        || (decoder->operand_count > 1
                            && decoder->operand[1].type
                                == CDISASM_OPERAND_MEMORY)
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ_WRITE;

            case CDISASM_X86_NAME_MOVLPS:
            case CDISASM_X86_NAME_MOVHPS:
            case CDISASM_X86_NAME_MOVLPD:
            case CDISASM_X86_NAME_MOVHPD:
                if (operand_index != 0) {
                    return CDISASM_OPERAND_ACCESS_READ;
                }
                return decoder->operand[0].type == CDISASM_OPERAND_MEMORY
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ_WRITE;

            default:
                return operand_index == 0
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_READ;
        }
    }
    if ((name_id >= CDISASM_X86_NAME_CMOVA
            && name_id <= CDISASM_X86_NAME_CMOVS)
        || (name_id >= CDISASM_X86_NAME_SETA
            && name_id <= CDISASM_X86_NAME_SETS)) {
        return operand_index == 0
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ;
    }

    switch (name_id) {
        case CDISASM_X86_NAME_MOV:
        case CDISASM_X86_NAME_MOVABS:
        case CDISASM_X86_NAME_MOVSX:
        case CDISASM_X86_NAME_MOVSXD:
        case CDISASM_X86_NAME_MOVZX:
        case CDISASM_X86_NAME_LEA:
        case CDISASM_X86_NAME_LAR:
        case CDISASM_X86_NAME_LSL:
        case CDISASM_X86_NAME_LFS:
        case CDISASM_X86_NAME_LGS:
        case CDISASM_X86_NAME_LSS:
        case CDISASM_X86_NAME_BSF:
        case CDISASM_X86_NAME_BSR:
        case CDISASM_X86_NAME_LZCNT:
        case CDISASM_X86_NAME_POPCNT:
        case CDISASM_X86_NAME_TZCNT:
        case CDISASM_X86_NAME_PF2ID:
        case CDISASM_X86_NAME_PF2IW:
        case CDISASM_X86_NAME_PFRCP:
        case CDISASM_X86_NAME_PFRSQRT:
        case CDISASM_X86_NAME_PI2FD:
        case CDISASM_X86_NAME_PI2FW:
        case CDISASM_X86_NAME_PSWAPD:
        case CDISASM_X86_NAME_MOVSB:
        case CDISASM_X86_NAME_MOVSD:
        case CDISASM_X86_NAME_MOVSQ:
        case CDISASM_X86_NAME_MOVSW:
        case CDISASM_X86_NAME_STOSB:
        case CDISASM_X86_NAME_STOSD:
        case CDISASM_X86_NAME_STOSQ:
        case CDISASM_X86_NAME_STOSW:
        case CDISASM_X86_NAME_LODSB:
        case CDISASM_X86_NAME_LODSD:
        case CDISASM_X86_NAME_LODSQ:
        case CDISASM_X86_NAME_LODSW:
        case CDISASM_X86_NAME_INSB:
        case CDISASM_X86_NAME_INSD:
        case CDISASM_X86_NAME_INSW:
        case CDISASM_X86_NAME_VMREAD:
            return operand_index == 0
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ;

        case CDISASM_X86_NAME_BT:
        case CDISASM_X86_NAME_CMPSB:
        case CDISASM_X86_NAME_CMPSD:
        case CDISASM_X86_NAME_CMPSQ:
        case CDISASM_X86_NAME_CMPSW:
        case CDISASM_X86_NAME_SCASB:
        case CDISASM_X86_NAME_SCASD:
        case CDISASM_X86_NAME_SCASQ:
        case CDISASM_X86_NAME_SCASW:
        case CDISASM_X86_NAME_OUTSB:
        case CDISASM_X86_NAME_OUTSD:
        case CDISASM_X86_NAME_OUTSW:
        case CDISASM_X86_NAME_OUT:
            return CDISASM_OPERAND_ACCESS_READ;

        case CDISASM_X86_NAME_POP:
        case CDISASM_X86_NAME_SGDT:
        case CDISASM_X86_NAME_SIDT:
        case CDISASM_X86_NAME_SLDT:
        case CDISASM_X86_NAME_SMSW:
        case CDISASM_X86_NAME_STR:
        case CDISASM_X86_NAME_VMPTRST:
            return operand_index == 0
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ;

        case CDISASM_X86_NAME_IN:
            return operand_index == 0
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ;

        case CDISASM_X86_NAME_IMUL:
            if (decoder->operand_count == 1) {
                return CDISASM_OPERAND_ACCESS_READ;
            }
            if (operand_index != 0) {
                return CDISASM_OPERAND_ACCESS_READ;
            }
            return decoder->operand_count == 2
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE;

        case CDISASM_X86_NAME_XCHG:
        case CDISASM_X86_NAME_XADD:
            return CDISASM_OPERAND_ACCESS_READ_WRITE;

        case CDISASM_X86_NAME_ADC:
        case CDISASM_X86_NAME_ADD:
        case CDISASM_X86_NAME_AND:
        case CDISASM_X86_NAME_ARPL:
        case CDISASM_X86_NAME_BTC:
        case CDISASM_X86_NAME_BTR:
        case CDISASM_X86_NAME_BTS:
        case CDISASM_X86_NAME_CMPXCHG:
        case CDISASM_X86_NAME_DEC:
        case CDISASM_X86_NAME_INC:
        case CDISASM_X86_NAME_NEG:
        case CDISASM_X86_NAME_NOT:
        case CDISASM_X86_NAME_OR:
        case CDISASM_X86_NAME_RCL:
        case CDISASM_X86_NAME_RCR:
        case CDISASM_X86_NAME_ROL:
        case CDISASM_X86_NAME_ROR:
        case CDISASM_X86_NAME_SAR:
        case CDISASM_X86_NAME_SBB:
        case CDISASM_X86_NAME_SHL:
        case CDISASM_X86_NAME_SHLD:
        case CDISASM_X86_NAME_SHR:
        case CDISASM_X86_NAME_SHRD:
        case CDISASM_X86_NAME_SUB:
        case CDISASM_X86_NAME_XOR:
        case CDISASM_X86_NAME_BSWAP:
        case CDISASM_X86_NAME_PAVGUSB:
        case CDISASM_X86_NAME_PFACC:
        case CDISASM_X86_NAME_PFADD:
        case CDISASM_X86_NAME_PFCMPEQ:
        case CDISASM_X86_NAME_PFCMPGE:
        case CDISASM_X86_NAME_PFCMPGT:
        case CDISASM_X86_NAME_PFMAX:
        case CDISASM_X86_NAME_PFMIN:
        case CDISASM_X86_NAME_PFMUL:
        case CDISASM_X86_NAME_PFNACC:
        case CDISASM_X86_NAME_PFPNACC:
        case CDISASM_X86_NAME_PFRCPIT1:
        case CDISASM_X86_NAME_PFRCPIT2:
        case CDISASM_X86_NAME_PFRSQIT1:
        case CDISASM_X86_NAME_PFSUB:
        case CDISASM_X86_NAME_PFSUBR:
        case CDISASM_X86_NAME_PMULHRW:
            return operand_index == 0
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_READ;

        default:
            return CDISASM_OPERAND_ACCESS_READ;
    }
}

static int first_operand_is_memory(const x86_decoder *decoder)
{
    return decoder->operand_count != 0
        && decoder->operand[0].type == CDISASM_OPERAND_MEMORY;
}

static void normalize_prefix_semantics(x86_decoder *decoder)
{
    uint32_t hle_prefix = CDISASM_PREFIX_NONE;

    decoder->prefix_flags &= ~(CDISASM_PREFIX_EFFECTIVE_MASK
        | CDISASM_PREFIX_HLE_MASK);

    if (decoder->repeat_prefix != 0
        && decoder_has_caps(decoder, X86_CAP_HLE)) {
        if (decoder->lock_prefix && decoder->lock_allowed) {
            hle_prefix = decoder->repeat_prefix == 0xf2
                ? CDISASM_PREFIX_XACQUIRE
                : CDISASM_PREFIX_XRELEASE;
        } else if (!decoder->lock_prefix
            && decoder->name_id == CDISASM_X86_NAME_XCHG
            && first_operand_is_memory(decoder)) {
            hle_prefix = decoder->repeat_prefix == 0xf2
                ? CDISASM_PREFIX_XACQUIRE
                : CDISASM_PREFIX_XRELEASE;
        } else if (!decoder->lock_prefix
            && decoder->repeat_prefix == 0xf3
            && decoder->name_id == CDISASM_X86_NAME_MOV
            && first_operand_is_memory(decoder)) {
            hle_prefix = CDISASM_PREFIX_XRELEASE;
        }
    }

    if (hle_prefix != CDISASM_PREFIX_NONE) {
        decoder->prefix_flags |= hle_prefix;
        decoder_require_caps(decoder, X86_CAP_HLE);
    }

    if (decoder->lock_prefix) {
        decoder->prefix_flags |= CDISASM_PREFIX_EFFECTIVE_LOCK;
        return;
    }
    if (hle_prefix != CDISASM_PREFIX_NONE) {
        return;
    }

    /* F2/F3 select, or are accepted as ignored prefixes on, these CET
     * shadow-stack, Key Locker, HRESET, CLZERO, and MCOMMIT encodings.  They
     * are never repeat actions. */
    if (decoder->name_id >= CDISASM_X86_NAME_CLRSSBSY
        && decoder->name_id <= CDISASM_X86_NAME_SETSSBSY) {
        return;
    }
    if (decoder->name_id >= CDISASM_X86_NAME_AESDEC128KL
        && decoder->name_id <= CDISASM_X86_NAME_AESENCWIDE256KL) {
        return;
    }
    if (decoder->name_id == CDISASM_X86_NAME_ENCODEKEY128
        || decoder->name_id == CDISASM_X86_NAME_ENCODEKEY256
        || decoder->name_id == CDISASM_X86_NAME_LOADIWKEY
        || decoder->name_id == CDISASM_X86_NAME_HRESET
        || decoder->name_id == CDISASM_X86_NAME_CLZERO
        || decoder->name_id == CDISASM_X86_NAME_RDPRU
        || decoder->name_id == CDISASM_X86_NAME_PREFETCHRST2
        || decoder->name_id == CDISASM_X86_NAME_PREFETCHWT1
        || decoder->name_id == CDISASM_X86_NAME_MCOMMIT
        || decoder->name_id == CDISASM_X86_NAME_PSMASH
        || decoder->name_id == CDISASM_X86_NAME_PVALIDATE
        || decoder->name_id == CDISASM_X86_NAME_RMPADJUST
        || decoder->name_id == CDISASM_X86_NAME_RMPUPDATE
        || decoder->name_id == CDISASM_X86_NAME_RDMSRLIST
        || decoder->name_id == CDISASM_X86_NAME_WRMSRLIST
        || decoder->name_id == CDISASM_X86_NAME_PTWRITE
        || decoder->name_id == CDISASM_X86_NAME_VMRUN
        || decoder->name_id == CDISASM_X86_NAME_VMSAVE) {
        return;
    }

    /* WAITPKG prefixes select opcodes and are never repeat actions. */
    if (decoder->name_id == CDISASM_X86_NAME_UMONITOR
        || decoder->name_id == CDISASM_X86_NAME_UMWAIT
        || decoder->name_id == CDISASM_X86_NAME_TPAUSE) {
        return;
    }

    /* F3 selects RDPID/WBNOINVD where implemented, and is an ignored
     * non-repeat prefix on the older WBINVD interpretation. */
    if (decoder->name_id == CDISASM_X86_NAME_RDPID
        || decoder->name_id == CDISASM_X86_NAME_WBINVD
        || decoder->name_id == CDISASM_X86_NAME_WBNOINVD
        || decoder->name_id == CDISASM_X86_NAME_ADOX
        || decoder->name_id == CDISASM_X86_NAME_RDFSBASE
        || decoder->name_id == CDISASM_X86_NAME_RDGSBASE
        || decoder->name_id == CDISASM_X86_NAME_WRFSBASE
        || decoder->name_id == CDISASM_X86_NAME_WRGSBASE
        || decoder->name_id == CDISASM_X86_NAME_BNDMK
        || decoder->name_id == CDISASM_X86_NAME_BNDCL
        || decoder->name_id == CDISASM_X86_NAME_BNDCU
        || decoder->name_id == CDISASM_X86_NAME_BNDCN
        || decoder->name_id == CDISASM_X86_NAME_CLUI
        || decoder->name_id == CDISASM_X86_NAME_SENDUIPI
        || decoder->name_id == CDISASM_X86_NAME_STUI
        || decoder->name_id == CDISASM_X86_NAME_TESTUI
        || decoder->name_id == CDISASM_X86_NAME_UIRET
        || decoder->name_id == CDISASM_X86_NAME_XSUSLDTRK
        || decoder->name_id == CDISASM_X86_NAME_XRESLDTRK
        || decoder->name_id == CDISASM_X86_NAME_ENQCMD
        || decoder->name_id == CDISASM_X86_NAME_ENQCMDS
        || decoder->name_id == CDISASM_X86_NAME_URDMSR
        || decoder->name_id == CDISASM_X86_NAME_UWRMSR
        || decoder->name_id == CDISASM_X86_NAME_AOR
        || decoder->name_id == CDISASM_X86_NAME_AXOR) {
        return;
    }

    /* F2/F3 preceding REX2 are encountered legacy prefixes, not REP. */
    if (decoder->rex2_present) {
        return;
    }

    /* F2/F3 are opcode selectors for legacy SIMD, never REP actions. */
    if ((decoder->required_caps
            & (X86_CAP_SSE | X86_CAP_SSE2 | X86_CAP_SSE3
                | X86_CAP_SSSE3 | X86_CAP_SSE41 | X86_CAP_SSE4A
                | X86_CAP_SSE42)) != 0) {
        return;
    }

    /* Redundant F2/F3 on x87 are encountered bytes, not REP actions. */
    if ((decoder->required_caps & X86_CAP_X87) != 0) {
        return;
    }

    /* These prefixes are encoding hints or ignored, never repeat actions. */
    if (decoder->name_id == CDISASM_X86_NAME_NOP
        || decoder->name_id == CDISASM_X86_NAME_PREFETCHIT0
        || decoder->name_id == CDISASM_X86_NAME_PREFETCHIT1
        || decoder->name_id == CDISASM_X86_NAME_MOV
        || decoder->name_id == CDISASM_X86_NAME_XCHG
        || decoder->name_id == CDISASM_X86_NAME_XBEGIN
        || decoder->name_id == CDISASM_X86_NAME_XABORT
        || decoder->name_id == CDISASM_X86_NAME_XEND
        || decoder->name_id == CDISASM_X86_NAME_XTEST) {
        return;
    }
    if (decoder->repeat_prefix == 0xf3) {
        decoder->prefix_flags |= CDISASM_PREFIX_EFFECTIVE_REP;
    } else if (decoder->repeat_prefix == 0xf2) {
        decoder->prefix_flags |= CDISASM_PREFIX_EFFECTIVE_REPNE;
    }
}

static const x86_x87_descriptor *x87_register_descriptor(
    uint8_t opcode,
    uint8_t modrm)
{
    size_t index;

    for (index = 0;
         index < sizeof(x86_x87_register_map)
            / sizeof(x86_x87_register_map[0]);
         ++index) {
        const x86_x87_register_range *range =
            &x86_x87_register_map[index];

        if (range->opcode == opcode
            && modrm >= range->first_modrm
            && modrm <= range->last_modrm) {
            return &range->descriptor;
        }
    }
    return NULL;
}

static const x86_x87_descriptor *x87_descriptor_for_bytes(
    uint8_t opcode,
    uint8_t modrm)
{
    if (opcode < 0xd8 || opcode > 0xdf) {
        return NULL;
    }
    if ((modrm >> 6) != 3) {
        const x86_x87_descriptor *descriptor =
            &x86_x87_memory_map[opcode - 0xd8][(modrm >> 3) & 7];

        return descriptor->form == X86_X87_FORM_INVALID
            ? NULL
            : descriptor;
    }
    return x87_register_descriptor(opcode, modrm);
}

static int is_legacy_prefix_byte(uint8_t byte)
{
    switch (byte) {
        case 0xf0:
        case 0xf2:
        case 0xf3:
        case 0x66:
        case 0x67:
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
        case 0x64:
        case 0x65:
            return 1;
        default:
            return 0;
    }
}

static int has_wait_x87_alias(
    const uint8_t *code,
    size_t code_size,
    cdisasm_mode mode)
{
    size_t position = 1;
    const x86_x87_descriptor *descriptor;

    if (code_size == 0 || code[0] != 0x9b) {
        return 0;
    }
    while (position < code_size
        && position < CDISASM_MAX_INSTRUCTION_SIZE) {
        uint8_t byte = code[position];

        if (is_legacy_prefix_byte(byte)
            || (mode == CDISASM_MODE_64
                && byte >= 0x40 && byte <= 0x4f)) {
            ++position;
            continue;
        }
        break;
    }
    if (position + 1 >= code_size
        || position + 1 >= CDISASM_MAX_INSTRUCTION_SIZE) {
        return 0;
    }
    descriptor = x87_descriptor_for_bytes(
        code[position], code[position + 1]);
    return descriptor != NULL
        && descriptor->wait_name_id != CDISASM_X86_NAME_NONE;
}

static uint64_t x87_feature_cap(uint8_t feature)
{
    switch ((x86_x87_feature)feature) {
        case X86_X87_FEATURE_BASE:
            return 0;
        case X86_X87_FEATURE_287:
            return X86_CAP_X87_287;
        case X86_X87_FEATURE_387:
            return X86_CAP_X87_387;
        case X86_X87_FEATURE_P6:
            return X86_CAP_P6;
        case X86_X87_FEATURE_SSE3:
            return X86_CAP_SSE3;
        default:
            return X86_CAP_ALL;
    }
}

static unsigned int x87_memory_bits(
    const x86_decoder *decoder,
    uint8_t size)
{
    switch ((x86_x87_size)size) {
        case X86_X87_SIZE_16:
        case X86_X87_SIZE_32:
        case X86_X87_SIZE_64:
        case X86_X87_SIZE_80:
            return size;
        case X86_X87_SIZE_ENV:
            return (decoder->mode == CDISASM_MODE_16)
                != (decoder->operand_override != 0)
                ? 14u * 8u
                : 28u * 8u;
        case X86_X87_SIZE_STATE:
            return (decoder->mode == CDISASM_MODE_16)
                != (decoder->operand_override != 0)
                ? 94u * 8u
                : 108u * 8u;
        default:
            return 0;
    }
}

static int add_x87_stack_operand(
    x86_decoder *decoder,
    unsigned int stack_index,
    cdisasm_operand_access access)
{
    if (stack_index >= 8) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    return add_named_register_operand_access(
        decoder,
        (cdisasm_x86_reg_id)(CDISASM_X86_REG_ST0 + stack_index),
        80,
        access);
}

static int decode_x87(x86_decoder *decoder, uint8_t opcode)
{
    const x86_x87_descriptor *descriptor;
    x86_modrm modrm;
    uint8_t modrm_byte;
    unsigned int bits;

    if (decoder->position >= decoder->code_size) {
        return decoder_fail(decoder, CDISASM_STATUS_TRUNCATED);
    }
    modrm_byte = decoder->code[decoder->position];
    descriptor = x87_descriptor_for_bytes(opcode, modrm_byte);
    if (descriptor == NULL) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }

    decoder_require_caps(decoder,
        X86_CAP_X87 | x87_feature_cap(descriptor->feature));
    if (decoder->wait_prefix) {
        if (descriptor->wait_name_id == CDISASM_X86_NAME_NONE) {
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
        }
        decoder->name_id = descriptor->wait_name_id;
    } else {
        decoder->name_id = descriptor->name_id;
    }

    switch ((x86_x87_form)descriptor->form) {
        case X86_X87_FORM_MEMORY_READ:
        case X86_X87_FORM_MEMORY_WRITE:
            if (modrm.is_register) {
                return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
            }
            bits = x87_memory_bits(decoder, descriptor->size);
            if (bits == 0
                || !add_rm_operand(decoder, &modrm, bits, 1)) {
                return 0;
            }
            return set_last_operand_access(
                decoder,
                descriptor->form == X86_X87_FORM_MEMORY_READ
                    ? CDISASM_OPERAND_ACCESS_READ
                    : CDISASM_OPERAND_ACCESS_WRITE);

        case X86_X87_FORM_ST0_STI_READ_WRITE:
            return add_x87_stack_operand(
                    decoder, 0, CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_x87_stack_operand(
                    decoder, modrm.rm3, CDISASM_OPERAND_ACCESS_READ);
        case X86_X87_FORM_STI_ST0_READ_WRITE:
            return add_x87_stack_operand(
                    decoder, modrm.rm3,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_x87_stack_operand(
                    decoder, 0, CDISASM_OPERAND_ACCESS_READ);
        case X86_X87_FORM_STI_ST0_WRITE:
            return add_x87_stack_operand(
                    decoder, modrm.rm3, CDISASM_OPERAND_ACCESS_WRITE)
                && add_x87_stack_operand(
                    decoder, 0, CDISASM_OPERAND_ACCESS_READ);
        case X86_X87_FORM_ST0_STI_WRITE:
            decoder->groups |= CDISASM_GROUP_CONDITIONAL;
            return add_x87_stack_operand(
                    decoder, 0, CDISASM_OPERAND_ACCESS_WRITE)
                && add_x87_stack_operand(
                    decoder, modrm.rm3, CDISASM_OPERAND_ACCESS_READ);
        case X86_X87_FORM_ST0_STI_READ:
            return add_x87_stack_operand(
                    decoder, 0, CDISASM_OPERAND_ACCESS_READ)
                && add_x87_stack_operand(
                    decoder, modrm.rm3, CDISASM_OPERAND_ACCESS_READ);
        case X86_X87_FORM_STI_READ:
            return add_x87_stack_operand(
                decoder, modrm.rm3, CDISASM_OPERAND_ACCESS_READ);
        case X86_X87_FORM_STI_WRITE:
            return add_x87_stack_operand(
                decoder, modrm.rm3, CDISASM_OPERAND_ACCESS_WRITE);
        case X86_X87_FORM_STI_READ_WRITE:
            return add_x87_stack_operand(
                decoder, modrm.rm3, CDISASM_OPERAND_ACCESS_READ_WRITE);
        case X86_X87_FORM_AX_WRITE:
            return add_named_register_operand_access(
                decoder,
                CDISASM_X86_REG_AX,
                16,
                CDISASM_OPERAND_ACCESS_WRITE);
        case X86_X87_FORM_FIXED:
            return 1;
        case X86_X87_FORM_INVALID:
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
}

static uint32_t mnemonic_status_flags(const x86_decoder *decoder)
{
    cdisasm_x86_name_id name_id = decoder->name_id;
    unsigned int condition;

    for (condition = 0u; condition < 16u; ++condition) {
        if (name_id == set_condition_name[condition]
            || name_id == apx_set_condition_name[condition]
            || name_id == move_condition_name[condition]
            || name_id == apx_move_condition_name[condition]) {
            return CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
        }
    }

    if (name_id == CDISASM_X86_NAME_CMPSD
        && decoder->operand_count == 2
        && decoder->operand[0].type == CDISASM_OPERAND_MEMORY
        && decoder->operand[1].type == CDISASM_OPERAND_MEMORY) {
        return CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    }
    if (name_id == CDISASM_X86_NAME_ANDN
        || name_id == CDISASM_X86_NAME_BEXTR
        || name_id == CDISASM_X86_NAME_BLSI
        || name_id == CDISASM_X86_NAME_BLSMSK
        || name_id == CDISASM_X86_NAME_BLSR
        || name_id == CDISASM_X86_NAME_BZHI) {
        return (decoder->prefix_flags & CDISASM_PREFIX_APX_NF) != 0
            ? 0u : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    }
    if (name_id == CDISASM_X86_NAME_NEG
        || name_id == CDISASM_X86_NAME_INC
        || name_id == CDISASM_X86_NAME_DEC) {
        return (decoder->prefix_flags & CDISASM_PREFIX_APX_NF) != 0
            ? 0u : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    }
    if (name_id == CDISASM_X86_NAME_ADD
        || name_id == CDISASM_X86_NAME_AND
        || name_id == CDISASM_X86_NAME_OR
        || name_id == CDISASM_X86_NAME_SUB
        || name_id == CDISASM_X86_NAME_XOR) {
        return (decoder->prefix_flags & CDISASM_PREFIX_APX_NF) != 0
            ? 0u : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    }
    if (name_id == CDISASM_X86_NAME_ROL
        || name_id == CDISASM_X86_NAME_ROR
        || name_id == CDISASM_X86_NAME_SHL
        || name_id == CDISASM_X86_NAME_SHLD
        || name_id == CDISASM_X86_NAME_SHR
        || name_id == CDISASM_X86_NAME_SHRD
        || name_id == CDISASM_X86_NAME_SAR) {
        return (decoder->prefix_flags & CDISASM_PREFIX_APX_NF) != 0
            ? 0u : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    }
    switch (name_id) {
        case CDISASM_X86_NAME_ADC:
        case CDISASM_X86_NAME_ADCX:
        case CDISASM_X86_NAME_ADOX:
        case CDISASM_X86_NAME_SBB:
        case CDISASM_X86_NAME_RCL:
        case CDISASM_X86_NAME_RCR:
        case CDISASM_X86_NAME_AAA:
        case CDISASM_X86_NAME_AAS:
        case CDISASM_X86_NAME_CMC:
        case CDISASM_X86_NAME_DAA:
        case CDISASM_X86_NAME_DAS:
            return CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;

        case CDISASM_X86_NAME_INTO:
        case CDISASM_X86_NAME_LAHF:
        case CDISASM_X86_NAME_LOOPE:
        case CDISASM_X86_NAME_LOOPNE:
        case CDISASM_X86_NAME_PUSHF:
        case CDISASM_X86_NAME_PUSHFD:
        case CDISASM_X86_NAME_PUSHFQ:
            return CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;

        case CDISASM_X86_NAME_AAD:
        case CDISASM_X86_NAME_AAM:
        case CDISASM_X86_NAME_ARPL:
        case CDISASM_X86_NAME_BSF:
        case CDISASM_X86_NAME_BSR:
        case CDISASM_X86_NAME_BT:
        case CDISASM_X86_NAME_BTC:
        case CDISASM_X86_NAME_BTR:
        case CDISASM_X86_NAME_BTS:
        case CDISASM_X86_NAME_CLC:
        case CDISASM_X86_NAME_CLD:
        case CDISASM_X86_NAME_CLI:
        case CDISASM_X86_NAME_AND:
        case CDISASM_X86_NAME_CMP:
        case CDISASM_X86_NAME_DEC:
        case CDISASM_X86_NAME_INC:
        case CDISASM_X86_NAME_OR:
        case CDISASM_X86_NAME_SUB:
        case CDISASM_X86_NAME_TEST:
        case CDISASM_X86_NAME_XOR:
        case CDISASM_X86_NAME_CMPSB:
        case CDISASM_X86_NAME_CMPSQ:
        case CDISASM_X86_NAME_CMPSW:
        case CDISASM_X86_NAME_SCASB:
        case CDISASM_X86_NAME_SCASD:
        case CDISASM_X86_NAME_SCASQ:
        case CDISASM_X86_NAME_SCASW:
        case CDISASM_X86_NAME_SAHF:
        case CDISASM_X86_NAME_POPF:
        case CDISASM_X86_NAME_POPFD:
        case CDISASM_X86_NAME_POPFQ:
        case CDISASM_X86_NAME_STC:
        case CDISASM_X86_NAME_STD:
        case CDISASM_X86_NAME_STI:
            return CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;

        default:
            return 0;
    }
}

static int finalize_instruction2(
    x86_decoder *decoder,
    cdisasm_instruction *instruction)
{
    unsigned int index;

    *instruction = (cdisasm_instruction){0};
    instruction->address = decoder->address;
    instruction->branch_target = decoder->branch_target;
    instruction->opcode_size = (uint32_t)decoder->position;
    instruction->opcode_groups = decoder->groups;
    instruction->opcode_flags = decoder->prefix_flags
        | mnemonic_status_flags(decoder);
    instruction->name_id = decoder->name_id;
    instruction->form_id = decoder->form_id;
    instruction->last_error_id = (uint8_t)CDISASM_STATUS_OK;
    instruction->operand_count = (uint8_t)decoder->operand_count;
    instruction->encoding = decoder->encoding;
    instruction->mask_reg = decoder->mask_reg;
    instruction->mask_mode = decoder->mask_mode;
    instruction->rounding = decoder->rounding;
    instruction->sae = decoder->sae;

    for (index = 0; index < decoder->operand_count; ++index) {
        const x86_operand *source = &decoder->operand[index];
        cdisasm_opcode *target = &instruction->opcode[index];

        target->type = source->type;
        target->reg = source->reg;
        target->base_reg = source->base_reg;
        target->index_reg = source->index_reg;
        target->size = source->size;
        target->scale = source->scale;
        target->segment_reg = source->segment_reg;
        target->flags = source->flags;
        target->access = decoded_operand_access(decoder, index);
        target->broadcast = source->broadcast;
        if (source->resolve_pc_address) {
            target->address = decoder->address + decoder->position + source->imm;
            if (source->base_reg == CDISASM_REG_EIP) {
                target->address = (uint32_t)target->address;
            }
        } else {
            target->address = source->address;
        }
        target->imm = source->imm;
    }
    if (!add_effective_encoding_groups(decoder, instruction)) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    return 1;
}

static cdisasm_status decode_core(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    x86_decoder *decoder)
{
    uint8_t opcode;

    *decoder = (x86_decoder){0};
    decoder->code = code;
    decoder->code_size = code_size;
    decoder->address = address;
    decoder->mode = mode;
    decoder->cpu_id = cpu_id;
    decoder->cpu_caps = cpu_capabilities(cpu_id);
#if USE_EXTRA_OPCODES
    decoder->cpu_extra_caps = cpu_extra_capabilities(cpu_id);
    decoder->cpu_extra_caps_high = cpu_extra_capabilities_high(cpu_id);
#endif
    decoder->error = CDISASM_STATUS_OK;

    if (has_wait_x87_alias(code, code_size, mode)) {
        decoder->position = 1;
        decoder->wait_prefix = 1;
        decoder->prefix_flags |= CDISASM_PREFIX_WAIT;
    }

    if (!parse_prefixes(decoder)) {
        return decoder->error;
    }
    decoder->encoding.prefix_size = (uint8_t)decoder->position;
    decoder->encoding.opcode_offset = (uint8_t)decoder->position;
    if (!read_u8(decoder, &opcode)) {
        return decoder->error;
    }
    decoder->encoding.opcode_size = 1;
    if (!decode_primary(decoder, opcode)) {
        return decoder->error == CDISASM_STATUS_OK
            ? CDISASM_STATUS_INVALID_INSTRUCTION
            : decoder->error;
    }
    if (decoder->error != CDISASM_STATUS_OK) {
        return decoder->error;
    }
    normalize_prefix_semantics(decoder);
    if (decoder->name_id == CDISASM_X86_NAME_NONE) {
        decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    } else if (decoder->position == 0
        || decoder->position > CDISASM_MAX_INSTRUCTION_SIZE) {
        decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    } else if (decoder->lock_prefix && !decoder->lock_allowed) {
        decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    } else {
        /* Required capabilities also drive the public ISA-group metadata. */
        decoder_require_caps(decoder, mnemonic_required_caps(decoder->name_id));
        if (cpu_id != CDISASM_CPU_X86
            && (decoder->required_caps & ~decoder->cpu_caps) != 0) {
            decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if USE_EXTRA_OPCODES
        if (cpu_id != CDISASM_CPU_X86
            && ((decoder->required_extra_caps
                    & ~decoder->cpu_extra_caps) != 0
                || (decoder->required_extra_caps_high
                    & ~decoder->cpu_extra_caps_high) != 0
                || ((decoder->required_extra_any_caps != 0
                        || decoder->required_extra_any_caps_high != 0)
                    && (decoder->required_extra_any_caps
                            & decoder->cpu_extra_caps) == 0
                    && (decoder->required_extra_any_caps_high
                            & decoder->cpu_extra_caps_high) == 0))) {
            decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#endif
    }
    return decoder->error;
}

cdisasm_status cdisasm_x86_decode_core(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    cdisasm_instruction *instruction)
{
    x86_decoder decoder;
    cdisasm_status status = decode_core(
        code,
        code_size,
        address,
        mode,
        cpu_id,
        &decoder);

    if (status != CDISASM_STATUS_OK) {
        return status;
    }
    if (!finalize_instruction2(&decoder, instruction)) {
        return decoder.error;
    }
    return CDISASM_STATUS_OK;
}

static int decode_moffs(x86_decoder *decoder, uint8_t opcode)
{
    uint64_t offset;
    unsigned int bits = (opcode == 0xa0 || opcode == 0xa2) ? 8u : decoder->operand_bits;
    cdisasm_x86_reg_id segment = segment_prefix_id(decoder->segment_prefix);
    uint8_t memory_flags = CDISASM_OPERAND_FLAG_ABSOLUTE
        | CDISASM_OPERAND_FLAG_HAS_ADDRESS;

    decoder->name_id = CDISASM_X86_NAME_MOV;
    if (!read_displacement_value(decoder, decoder->address_bits, &offset)) {
        return 0;
    }
    if (segment != CDISASM_REG_NONE) {
        memory_flags |= CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
    }

    if (opcode == 0xa0 || opcode == 0xa1) {
        return add_register_operand(decoder, 0, bits)
            && add_memory_operand(
                decoder,
                bits,
                CDISASM_REG_NONE,
                CDISASM_REG_NONE,
                0,
                segment,
                memory_flags,
                offset,
                0);
    }
    return add_memory_operand(
            decoder,
            bits,
            CDISASM_REG_NONE,
            CDISASM_REG_NONE,
            0,
            segment,
            memory_flags,
            offset,
            0)
        && add_register_operand(decoder, 0, bits);
}

static int add_string_memory_operand(
    x86_decoder *decoder,
    unsigned int bits,
    int destination)
{
    cdisasm_x86_reg_id segment = destination
        ? CDISASM_REG_ES
        : segment_prefix_id(decoder->segment_prefix);
    uint8_t flags = CDISASM_OPERAND_FLAG_IMPLICIT;

    if (!destination && segment != CDISASM_REG_NONE) {
        flags |= CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
    }
    return add_memory_operand(
        decoder,
        bits,
        gpr_id(destination ? 7u : 6u, decoder->address_bits, 1),
        CDISASM_REG_NONE,
        0,
        segment,
        flags,
        0,
        0);
}

static int decode_string_instruction(x86_decoder *decoder, uint8_t opcode)
{
    unsigned int bits = (opcode & 1u) == 0 ? 8u : decoder->operand_bits;
    unsigned int operation;
    unsigned int size_index;

    switch (bits) {
        case 8:
            size_index = 0;
            break;
        case 16:
            size_index = 1;
            break;
        case 32:
            size_index = 2;
            break;
        case 64:
            size_index = 3;
            break;
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }

    switch (opcode & 0xfeu) {
        case 0xa4:
            operation = 0;
            break;
        case 0xa6:
            operation = 1;
            break;
        case 0xaa:
            operation = 2;
            break;
        case 0xac:
            operation = 3;
            break;
        case 0xae:
            operation = 4;
            break;
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }

    decoder->name_id = string_instruction_name[operation][size_index];

    switch (operation) {
        case 0:
            return add_string_memory_operand(decoder, bits, 1)
                && add_string_memory_operand(decoder, bits, 0);
        case 1:
            return add_string_memory_operand(decoder, bits, 0)
                && add_string_memory_operand(decoder, bits, 1);
        case 2:
            return add_string_memory_operand(decoder, bits, 1)
                && add_register_operand_flags(
                    decoder,
                    0,
                    bits,
                    CDISASM_OPERAND_FLAG_IMPLICIT);
        case 3:
            return add_register_operand_flags(
                    decoder,
                    0,
                    bits,
                    CDISASM_OPERAND_FLAG_IMPLICIT)
                && add_string_memory_operand(decoder, bits, 0);
        case 4:
            return add_register_operand_flags(
                    decoder,
                    0,
                    bits,
                    CDISASM_OPERAND_FLAG_IMPLICIT)
                && add_string_memory_operand(decoder, bits, 1);
        default:
            return 0;
    }
}

static int decode_string_io(x86_decoder *decoder, uint8_t opcode)
{
    unsigned int bits = (opcode & 1u) == 0 ? 8u : decoder->operand_bits;
    unsigned int size_index;

    if (bits == 64) {
        bits = 32;
    }
    size_index = bits == 8 ? 0u : bits == 16 ? 1u : 2u;
    decoder->name_id = string_io_name[opcode < 0x6e ? 0 : 1][size_index];
    if (opcode < 0x6e) {
        return add_string_memory_operand(decoder, bits, 1)
            && add_named_register_operand(
                decoder,
                CDISASM_REG_DX,
                16,
                CDISASM_OPERAND_FLAG_IMPLICIT);
    }
    return add_named_register_operand(
            decoder,
            CDISASM_REG_DX,
            16,
            CDISASM_OPERAND_FLAG_IMPLICIT)
        && add_string_memory_operand(decoder, bits, 0);
}

static int decode_mov_rm_immediate(x86_decoder *decoder, uint8_t opcode)
{
    x86_modrm modrm;
    unsigned int bits = opcode == 0xc6 ? 8u : decoder->operand_bits;
    unsigned int immediate_bits = bits == 64 ? 32u : bits;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }

    /* C6/C7 with the exact F8 ModRM byte are RTM opcodes rather than the
     * otherwise-invalid /7 members of the MOV-immediate groups.  Claim and
     * consume these shapes even in an extra-opcode-OFF build so valid RTM is
     * reported as unsupported rather than malformed. */
    if (decoder->encoding.modrm == UINT8_C(0xf8)) {
        if (decoder->lock_prefix || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (opcode == UINT8_C(0xc6)) {
            uint64_t immediate;

            if (!read_immediate_value(decoder, 8, &immediate)) {
                return 0;
            }
#if !USE_EXTRA_OPCODES
            (void)immediate;
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
            decoder->name_id = CDISASM_X86_NAME_XABORT;
            decoder_require_extra(decoder, CDISASM_X86_GROUP_RTM);
            return add_immediate_value(decoder, 8, immediate, 0);
#endif
        }
        decoder->name_id = CDISASM_X86_NAME_XBEGIN;
        decoder->groups |= CDISASM_GROUP_JUMP
            | CDISASM_GROUP_RELATIVE_BRANCH
            | CDISASM_GROUP_CONDITIONAL;
        /* XBEGIN encodes rel16 for an effective 16-bit operand size and rel32
         * for both effective 32- and 64-bit operand sizes.  Consequently an
         * effective REX.W takes precedence over an earlier 66 prefix, while a
         * legacy prefix after REX cancels that REX in the prefix parser. */
        if (!add_relative_operand(
                decoder,
                decoder->operand_bits == 64u
                    ? 32u
                    : decoder->operand_bits)) {
            return 0;
        }
        /* Outside 64-bit mode, Intel defines the fallback as a 32-bit EIP
         * computation even for the rel16 form.  Therefore rel16 must not
         * truncate at 16 bits, but either form must wrap at the EIP boundary
         * rather than leaking a 33-bit target through the public metadata. */
        if (decoder->mode != CDISASM_MODE_64) {
            const uint64_t target = (uint32_t)decoder->branch_target;

            decoder->branch_target = target;
            decoder->operand[decoder->operand_count - 1u].imm = target;
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder_require_extra(decoder, CDISASM_X86_GROUP_RTM);
        return 1;
#endif
    }
    if (modrm.reg3 != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->name_id = CDISASM_X86_NAME_MOV;
    return add_rm_operand(decoder, &modrm, bits, 1)
        && add_immediate_operand(decoder, immediate_bits, bits == 64);
}

static int decode_group4(x86_decoder *decoder)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.reg3 > 1) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->name_id = modrm.reg3 == 0 ? CDISASM_X86_NAME_INC : CDISASM_X86_NAME_DEC;
    if (!modrm.is_register) {
        decoder->lock_allowed = 1;
    }
    return add_rm_operand(decoder, &modrm, 8, 1);
}

static int decode_group5(x86_decoder *decoder)
{
    x86_modrm modrm;
    unsigned int bits = decoder->operand_bits;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    switch (modrm.reg3) {
        case 0:
            decoder->name_id = CDISASM_X86_NAME_INC;
            if (!modrm.is_register) {
                decoder->lock_allowed = 1;
            }
            break;
        case 1:
            decoder->name_id = CDISASM_X86_NAME_DEC;
            if (!modrm.is_register) {
                decoder->lock_allowed = 1;
            }
            break;
        case 2:
            decoder->name_id = CDISASM_X86_NAME_CALL;
            decoder->groups |= CDISASM_GROUP_CALL;
            bits = decoder->mode == CDISASM_MODE_64 ? 64u : decoder->operand_bits;
            break;
        case 3:
            return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        case 4:
            decoder->name_id = CDISASM_X86_NAME_JMP;
            decoder->groups |= CDISASM_GROUP_JUMP;
            bits = decoder->mode == CDISASM_MODE_64 ? 64u : decoder->operand_bits;
            break;
        case 5:
            return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        case 6:
            decoder->name_id = CDISASM_X86_NAME_PUSH;
            bits = decoder->mode == CDISASM_MODE_64
                ? (decoder->operand_override ? 16u : 64u)
                : decoder->operand_bits;
            break;
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    return add_rm_operand(decoder, &modrm, bits, 1);
}

static int decode_enter(x86_decoder *decoder)
{
    decoder->name_id = CDISASM_X86_NAME_ENTER;
    return add_immediate_operand(decoder, 16, 0)
        && add_immediate_operand(decoder, 8, 0);
}

static int decode_io_immediate(x86_decoder *decoder, uint8_t opcode)
{
    unsigned int bits = (opcode & 1u) == 0 ? 8u : decoder->operand_bits;
    uint64_t value;

    if (bits == 64) {
        bits = 32;
    }

    if (!read_immediate_value(decoder, 8, &value)) {
        return 0;
    }
    decoder->name_id = opcode < 0xe6 ? CDISASM_X86_NAME_IN : CDISASM_X86_NAME_OUT;
    if (opcode < 0xe6) {
        return add_register_operand_flags(
                decoder,
                0,
                bits,
                CDISASM_OPERAND_FLAG_IMPLICIT)
            && add_immediate_value(decoder, 8, value, 0);
    }
    return add_immediate_value(decoder, 8, value, 0)
        && add_register_operand_flags(
            decoder,
            0,
            bits,
            CDISASM_OPERAND_FLAG_IMPLICIT);
}

static int decode_io_dx(x86_decoder *decoder, uint8_t opcode)
{
    unsigned int bits = (opcode & 1u) == 0 ? 8u : decoder->operand_bits;

    if (bits == 64) {
        bits = 32;
    }

    decoder->name_id = opcode < 0xee ? CDISASM_X86_NAME_IN : CDISASM_X86_NAME_OUT;
    if (opcode < 0xee) {
        return add_register_operand_flags(
                decoder,
                0,
                bits,
                CDISASM_OPERAND_FLAG_IMPLICIT)
            && add_named_register_operand(
                decoder,
                CDISASM_REG_DX,
                16,
                CDISASM_OPERAND_FLAG_IMPLICIT);
    }
    return add_named_register_operand(
            decoder,
            CDISASM_REG_DX,
            16,
            CDISASM_OPERAND_FLAG_IMPLICIT)
        && add_register_operand_flags(
            decoder,
            0,
            bits,
            CDISASM_OPERAND_FLAG_IMPLICIT);
}

/*
 * Return a positive x86_vex_extra_form for a defined pp/opcode combination,
 * zero for a reserved selector on a recognized opcode, and -1 when this
 * optional tranche does not own the opcode at all.
 */
static int vex_extra_form_for_encoding(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w)
{
    if (map_select == UINT8_C(2)) {
        if (is_packed_integer_minmax_opcode(map_select, opcode)) {
            /* VPMIN/MAX{SB,SD,UW,UD} own their complete map-2 opcode
             * rows.  Only mandatory 66 is allocated and W is ignored. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PACKED_INTEGER : 0;
        }
        if (is_vpmovsx_opcode(opcode)) {
            /* VPMOVSX{BW,BD,BQ,WD,WQ,DQ} own their complete map-2 opcode
             * rows.  Only mandatory 66 is allocated; W is ignored and the
             * dedicated decoder enforces NOVSR after consuming addressing. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PMOVSX_WIDEN : 0;
        }
        if (is_vpmovzx_opcode(opcode)) {
            /* VPMOVZX{BW,BD,BQ,WD,WQ,DQ} own their complete map-2 opcode
             * rows.  Only mandatory 66 is allocated; W is ignored and the
             * dedicated decoder enforces NOVSR after consuming addressing. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PMOVZX_WIDEN : 0;
        }
        if (is_vphminposuw_opcode(opcode)) {
            /* VPHMINPOSUW owns the complete map-2 opcode row.  Only pp=66
             * is allocated; its decoder enforces NOVSR and L=0 after
             * consuming the complete ModRM/address payload. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PHMINPOSUW : 0;
        }
        if (is_horizontal_integer_opcode(opcode)) {
            /* These six horizontal add/sub rows own every pp selector;
             * mandatory 66 is allocated and W is ignored. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_HORIZONTAL_INTEGER : 0;
        }
        if (is_vpsign_integer_opcode(opcode)) {
            /* VPSIGNB/W/D own their complete VEX map-2 opcode rows.  Only
             * pp=66 is allocated; W is ignored by the dedicated decoder. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_SIGN_INTEGER : 0;
        }
        if (opcode == UINT8_C(0x17)) {
            /* VPTEST owns its complete map-2 opcode row.  Only pp=66 is
             * allocated; W is ignored and NOVSR is enforced after the
             * complete ModRM/address payload has been consumed. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PTEST : 0;
        }
        if (opcode == UINT8_C(0x0e) || opcode == UINT8_C(0x0f)) {
            /* VTESTPS/PD own their complete map-2 opcode rows.  Only pp=66
             * and W=0 are allocated; their dedicated decoder also enforces
             * NOVSR after consuming ModRM/addressing. */
            return prefix == X86_SIMD_PREFIX_P66 && w == 0
                ? X86_VEX_EXTRA_FORM_TEST_PACKED : 0;
        }
        if (opcode == UINT8_C(0x18) || opcode == UINT8_C(0x19)) {
            /* VBROADCASTSS/SD own their complete map-2 opcode rows.  Their
             * dedicated decoder consumes ModRM/addressing before rejecting
             * reserved pp/W/L/vvvv controls. */
            if (prefix != X86_SIMD_PREFIX_P66) {
                return 0;
            }
            return opcode == UINT8_C(0x18)
                ? X86_VEX_EXTRA_FORM_BROADCAST_SCALAR_SINGLE
                : X86_VEX_EXTRA_FORM_BROADCAST_SCALAR_DOUBLE;
        }
        if (opcode == UINT8_C(0x1a) || opcode == UINT8_C(0x5a)) {
            /* VBROADCASTF128/I128 own their complete map-2 opcode rows.
             * The dedicated decoder consumes ModRM/addressing before
             * rejecting reserved pp/W/L/vvvv/register controls. */
            if (prefix != X86_SIMD_PREFIX_P66) {
                return 0;
            }
            return opcode == UINT8_C(0x1a)
                ? X86_VEX_EXTRA_FORM_BROADCAST_F128
                : X86_VEX_EXTRA_FORM_BROADCAST_I128;
        }
        if (opcode == UINT8_C(0x58) || opcode == UINT8_C(0x59)
            || opcode == UINT8_C(0x78) || opcode == UINT8_C(0x79)) {
            /* VPBROADCASTD/Q/B/W own their complete map-2 opcode rows.  pp=66
             * is allocated; the dedicated decoder consumes ModRM/addressing
             * before reporting every other selector as reserved. */
            if (prefix != X86_SIMD_PREFIX_P66) {
                return 0;
            }
            if (opcode == UINT8_C(0x58)) {
                return X86_VEX_EXTRA_FORM_BROADCAST_DWORD;
            }
            if (opcode == UINT8_C(0x59)) {
                return X86_VEX_EXTRA_FORM_BROADCAST_QWORD;
            }
            return opcode == UINT8_C(0x78)
                ? X86_VEX_EXTRA_FORM_BROADCAST_BYTE
                : X86_VEX_EXTRA_FORM_BROADCAST_WORD;
        }
        if (opcode == UINT8_C(0x29) || opcode == UINT8_C(0x2b)
            || opcode == UINT8_C(0x37)) {
            /* VPCMPEQQ, VPACKUSDW, and VPCMPGTQ own their complete VEX
             * selector rows. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PACKED_INTEGER : 0;
        }
        if (opcode >= UINT8_C(0x1c) && opcode <= UINT8_C(0x1e)) {
            /* VPABSB/W/D own the complete VEX map-2 opcode rows.  pp=66 is
             * allocated and every other pp selector is reserved. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_UNARY_VECTOR : 0;
        }
        if (opcode == UINT8_C(0x45) || opcode == UINT8_C(0x47)) {
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_VARIABLE_SHIFT : 0;
        }
        if (opcode == UINT8_C(0x46)) {
            return prefix == X86_SIMD_PREFIX_P66 && w == 0
                ? X86_VEX_EXTRA_FORM_VARIABLE_SHIFT : 0;
        }
        return -1;
    }
    if (map_select != UINT8_C(1)) {
        return -1;
    }
    if (is_vpunpck_integer_opcode(opcode)) {
        /* The packed-integer unpack opcodes own their complete VEX rows;
         * only the mandatory-66 selector is allocated. */
        return prefix == X86_SIMD_PREFIX_P66
            ? X86_VEX_EXTRA_FORM_UNPACK_INTEGER : 0;
    }
    switch (opcode) {
        case 0x14:
        case 0x15:
            /* VUNPCK{H,L}{PS,PD} own both complete VEX map-1 opcode rows.
             * pp=none and pp=66 are allocated; F2/F3 are reserved. */
            return prefix == X86_SIMD_PREFIX_NONE
                    || prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_UNPACK_PACKED : 0;
        case 0x2e:
        case 0x2f:
            /* VUCOMISS/SD and VCOMISS/SD each own their complete VEX map-1
             * opcode row. pp=none and pp=66 are allocated; F2/F3 are
             * reserved. */
            return prefix == X86_SIMD_PREFIX_NONE
                    || prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_UCOMI_SCALAR : 0;
        case 0xc2:
            /* VCMPPS/PD/SS/SD jointly allocate all four pp selectors on
             * the complete VEX map-1 opcode row.  W is ignored; the
             * dedicated decoder interprets L for packed forms and consumes
             * the mandatory trailing predicate byte. */
            return X86_VEX_EXTRA_FORM_COMPARE_FP_IMM8;
        case 0xc6:
            /* VSHUFPS/PD own the complete VEX map-1 opcode row.  pp=none
             * and pp=66 are allocated; F2/F3 are reserved. */
            return prefix <= X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_SHUF_PACKED : 0;
        case 0x63:
        case 0x67:
        case 0x6b:
            /* VPACKSSWB, VPACKUSWB and VPACKSSDW own every pp selector;
             * only pp=66 is allocated. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PACKED_INTEGER : 0;
        case 0x10:
        case 0x11:
            if (prefix == X86_SIMD_PREFIX_NONE
                || prefix == X86_SIMD_PREFIX_P66) {
                return opcode == UINT8_C(0x10)
                    ? X86_VEX_EXTRA_FORM_MOVE_LOAD
                    : X86_VEX_EXTRA_FORM_MOVE_STORE;
            }
            /* F2/F3 select scalar VMOVSD/VMOVSS forms owned by a later
             * descriptor tranche rather than a reserved encoding. */
            return -1;
        case 0x28:
        case 0x29:
            return prefix == X86_SIMD_PREFIX_NONE
                    || prefix == X86_SIMD_PREFIX_P66
                ? (opcode == UINT8_C(0x28)
                    ? X86_VEX_EXTRA_FORM_MOVE_LOAD
                    : X86_VEX_EXTRA_FORM_MOVE_STORE)
                : 0;
        case 0x2b:
            return prefix == X86_SIMD_PREFIX_NONE
                    || prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_MOVE_STORE_MEMORY
                : 0;
        case 0x50:
            return prefix == X86_SIMD_PREFIX_NONE
                    || prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_MOVE_MASK
                : 0;
        case 0xd7:
            /* VPMOVMSKB owns the complete VEX map-1/D7 row.  Only pp=66
             * is allocated; its dedicated decoder consumes ModRM/addressing
             * before rejecting vvvv, memory, or reserved selectors. */
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PMOVMSKB : 0;
        case 0x6f:
        case 0x7f:
            return prefix == X86_SIMD_PREFIX_P66
                    || prefix == X86_SIMD_PREFIX_PF3
                ? (opcode == UINT8_C(0x6f)
                    ? X86_VEX_EXTRA_FORM_MOVE_LOAD
                    : X86_VEX_EXTRA_FORM_MOVE_STORE)
                : 0;
        case 0x70:
            /* VPSHUFD/HW/LW jointly own the complete map-1 opcode row.
             * pp=none is reserved; 66/F3/F2 select the three families. */
            return prefix == X86_SIMD_PREFIX_NONE
                ? 0 : X86_VEX_EXTRA_FORM_SHUF_INTEGER;
        case 0xe7:
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_MOVE_STORE_MEMORY : 0;
        case 0xf0:
            return prefix == X86_SIMD_PREFIX_PF2
                ? X86_VEX_EXTRA_FORM_MOVE_LOAD_MEMORY : 0;
        case 0x54:
        case 0x55:
        case 0x57:
            return prefix <= X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PACKED_FP
                : 0;
        case 0x56:
            /* VOR owns all four pp selectors.  F2/F3 are reserved, but
             * their complete ModRM/address payload is consumed before the
             * selector error is published. */
            return prefix <= X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PACKED_FP : 0;
        case 0x58:
        case 0x59:
        case 0x5c:
        case 0x5d:
        case 0x5e:
        case 0x5f:
            return prefix <= X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PACKED_FP
                : X86_VEX_EXTRA_FORM_SCALAR_FP;
        case 0x51:
            return prefix <= X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_UNARY_VECTOR
                : X86_VEX_EXTRA_FORM_SCALAR_FP;
        case 0x52:
        case 0x53:
            if (prefix == X86_SIMD_PREFIX_NONE) {
                return X86_VEX_EXTRA_FORM_UNARY_VECTOR;
            }
            return prefix == X86_SIMD_PREFIX_PF3
                ? X86_VEX_EXTRA_FORM_SCALAR_FP
                : 0;
        case 0x5a:
            if (prefix == X86_SIMD_PREFIX_NONE) {
                return X86_VEX_EXTRA_FORM_UNARY_WIDEN;
            }
            if (prefix == X86_SIMD_PREFIX_P66) {
                return X86_VEX_EXTRA_FORM_UNARY_NARROW;
            }
            return X86_VEX_EXTRA_FORM_SCALAR_FP;
        case 0x5b:
            return prefix == X86_SIMD_PREFIX_PF2
                ? 0
                : X86_VEX_EXTRA_FORM_UNARY_VECTOR;
        case 0x7c:
        case 0x7d:
        case 0xd0:
            return prefix == X86_SIMD_PREFIX_P66
                    || prefix == X86_SIMD_PREFIX_PF2
                ? X86_VEX_EXTRA_FORM_PACKED_FP
                : 0;
        case 0xe6:
            if (prefix == X86_SIMD_PREFIX_PF3) {
                return X86_VEX_EXTRA_FORM_UNARY_WIDEN;
            }
            return prefix == X86_SIMD_PREFIX_P66
                    || prefix == X86_SIMD_PREFIX_PF2
                ? X86_VEX_EXTRA_FORM_UNARY_NARROW
                : 0;
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x74:
        case 0x75:
        case 0x76:
        case 0xd4:
        case 0xd5:
        case 0xd8:
        case 0xd9:
        case 0xda:
        case 0xdb:
        case 0xdc:
        case 0xdd:
        case 0xde:
        case 0xdf:
        case 0xe0:
        case 0xe3:
        case 0xe8:
        case 0xe9:
        case 0xea:
        case 0xeb:
        case 0xec:
        case 0xed:
        case 0xee:
        case 0xef:
        case 0xf4:
        case 0xf5:
        case 0xf6:
        case 0xf8:
        case 0xf9:
        case 0xfa:
        case 0xfb:
        case 0xfc:
        case 0xfd:
        case 0xfe:
            return prefix == X86_SIMD_PREFIX_P66
                ? X86_VEX_EXTRA_FORM_PACKED_INTEGER
                : 0;
        default:
            return -1;
    }
}

#if USE_EXTRA_OPCODES
static const x86_vex_extra_descriptor *find_vex_extra_descriptor(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w)
{
    size_t index;

    for (index = 0;
         index < sizeof(x86_vex_extra_map) / sizeof(x86_vex_extra_map[0]);
         ++index) {
        const x86_vex_extra_descriptor *descriptor =
            &x86_vex_extra_map[index];

        if (descriptor->map == map_select
            && descriptor->opcode == opcode
            && descriptor->prefix == prefix
            && (descriptor->w == 2 || descriptor->w == w)) {
            return descriptor;
        }
    }
    return NULL;
}
#endif

static uint8_t vex_rex_bits(
    uint8_t vex_map,
    uint8_t vex,
    int two_byte)
{
    uint8_t rex = 0;

    if (!two_byte && (vex & UINT8_C(0x80)) != 0) {
        rex |= UINT8_C(0x08);
    }
    if ((two_byte ? vex : vex_map) < UINT8_C(0x80)) {
        rex |= UINT8_C(0x04);
    }
    if (!two_byte) {
        if ((vex_map & UINT8_C(0x40)) == 0) {
            rex |= UINT8_C(0x02);
        }
        if ((vex_map & UINT8_C(0x20)) == 0) {
            rex |= UINT8_C(0x01);
        }
    }
    return rex;
}

static int vex_non64_extensions_are_valid(
    const x86_decoder *decoder,
    const x86_modrm *modrm,
    unsigned int source_index)
{
    return decoder->mode == CDISASM_MODE_64
        || (modrm->reg < 8
            && source_index < 8
            && (!modrm->is_register || modrm->rm < 8)
            && (modrm->base < 0 || modrm->base < 8)
            && (modrm->index < 0 || modrm->index < 8));
}

static int vex_vmovdq_non64_b_is_ignored(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t vex)
{
    const uint8_t prefix = vex & UINT8_C(0x03);

    /* The non-long VEX encodings of VMOVD/VMOVQ cannot name extended GPRs,
     * vector registers, or address bases.  Pinned XED consequently treats
     * inverted VEX.B as ignored for their fixed VL128/NOVSR rows.  Keep the
     * exception limited to the four selectors shared by those two iclasses;
     * C4 disambiguation still fixes raw R/X to 11 outside long mode. */
    return map_select == UINT8_C(1)
        && (vex & UINT8_C(0x7c)) == UINT8_C(0x78)
        && ((opcode == UINT8_C(0x6e)
                && prefix == X86_SIMD_PREFIX_P66)
            || (opcode == UINT8_C(0x7e)
                && (prefix == X86_SIMD_PREFIX_P66
                    || prefix == X86_SIMD_PREFIX_PF3))
            || (opcode == UINT8_C(0xd6)
                && prefix == X86_SIMD_PREFIX_P66));
}

static int vex_vmov_non64_b_is_ignored(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t vex)
{
    /* VMOVSD/VMOVSS are LIG/WIG, the duplicate moves are WIG, and the
     * unaligned packed moves are ordinary VL-selected WIG forms.  All six
     * rows ignore their VEX.B extension outside long mode.  Raw R/X remain
     * fixed by C4/LES disambiguation; the scalar NDS high bit is likewise
     * ignored for register forms, but memory forms retain fixed vvvv. */
    return map_select == UINT8_C(1)
        && (((opcode == UINT8_C(0x10) || opcode == UINT8_C(0x11))
                && ((vex & UINT8_C(0x03)) == X86_SIMD_PREFIX_NONE
                    || (vex & UINT8_C(0x03)) == X86_SIMD_PREFIX_P66
                    || (vex & UINT8_C(0x03)) == X86_SIMD_PREFIX_PF2
                    || (vex & UINT8_C(0x03)) == X86_SIMD_PREFIX_PF3))
            || ((opcode == UINT8_C(0x12) || opcode == UINT8_C(0x16))
                && (vex & UINT8_C(0x03)) == X86_SIMD_PREFIX_PF3));
}

static int vex_map3_classic_non64_b_is_ignored(
    uint8_t map_select,
    uint8_t opcode)
{
    /* Pinned XED treats inverted VEX.B as ignored outside long mode for the
     * classic map-3 immediate permutations and rounding, lane
     * insert/extract, blend, dot-product, and VMPSADBW rows. R/X remain
     * fixed by C4/LES disambiguation, while their dedicated decoders consume
     * ModRM/addressing and the trailing byte before classifying reserved
     * selectors. */
    return (map_select == UINT8_C(1)
            && (opcode == UINT8_C(0xc4) || opcode == UINT8_C(0xc5)))
        || (map_select == UINT8_C(3)
        && (opcode == UINT8_C(0x00)
            || opcode == UINT8_C(0x01)
            || opcode == UINT8_C(0x02)
            || opcode == UINT8_C(0x04)
            || opcode == UINT8_C(0x05)
            || opcode == UINT8_C(0x06)
            || opcode == UINT8_C(0x08)
            || opcode == UINT8_C(0x09)
            || opcode == UINT8_C(0x0a)
            || opcode == UINT8_C(0x0b)
            || opcode == UINT8_C(0x0c)
            || opcode == UINT8_C(0x0d)
            || opcode == UINT8_C(0x0e)
            || opcode == UINT8_C(0x17)
            || opcode == UINT8_C(0x18)
            || opcode == UINT8_C(0x19)
            || opcode == UINT8_C(0x21)
            || opcode == UINT8_C(0x38)
            || opcode == UINT8_C(0x39)
            || opcode == UINT8_C(0x46)
            || opcode == UINT8_C(0x4a)
            || opcode == UINT8_C(0x4b)
            || opcode == UINT8_C(0x4c)
            || opcode == UINT8_C(0x40)
            || opcode == UINT8_C(0x41)
            || opcode == UINT8_C(0x42)
            || opcode == UINT8_C(0x14)
            || opcode == UINT8_C(0x15)
            || opcode == UINT8_C(0x16)
            || opcode == UINT8_C(0x20)
            || opcode == UINT8_C(0x22)));
}

static int vex_vpbroadcast_non64_b_is_ignored(
    uint8_t map_select,
    uint8_t opcode)
{
    /* Once C4 has been distinguished from LES by raw R'=X'=1, pinned XED
     * treats B' as ignored for the non-long AVX/AVX2 VEX broadcast rows. */
    return map_select == UINT8_C(2)
        && (opcode == UINT8_C(0x18) || opcode == UINT8_C(0x19)
            || opcode == UINT8_C(0x1a) || opcode == UINT8_C(0x5a)
            || opcode == UINT8_C(0x58) || opcode == UINT8_C(0x59)
            || opcode == UINT8_C(0x78) || opcode == UINT8_C(0x79));
}

static int vex_map2_permute_non64_b_is_ignored(
    uint8_t map_select,
    uint8_t opcode)
{
    /* VPERMD/VPERMPS and variable-control VPERMILPD/VPERMILPS use the same
     * eight-register aliasing policy as the classic map-3 NDS rows once raw
     * R'=X'=1 has selected C4 over LES. */
    return map_select == UINT8_C(2)
        && (opcode == UINT8_C(0x0c) || opcode == UINT8_C(0x0d)
            || opcode == UINT8_C(0x16) || opcode == UINT8_C(0x36));
}

static int vex_vmaskmov_non64_b_is_ignored(
    uint8_t map_select,
    uint8_t opcode)
{
    /* The classic VMASKMOV and VPMASKMOV memory rows alias inverted VEX.B
     * and the high vvvv bit onto the low eight address/mask registers outside
     * long mode.  Raw R/X remain fixed by C4/LES disambiguation. */
    return map_select == UINT8_C(2)
        && ((opcode >= UINT8_C(0x2c) && opcode <= UINT8_C(0x2f))
            || opcode == UINT8_C(0x8c) || opcode == UINT8_C(0x8e));
}

static int vex_kmask_encoding_owned(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix)
{
    (void)prefix;
    if (map_select == 1) {
        switch (opcode) {
            case 0x41:
            case 0x42:
            case 0x44:
            case 0x45:
            case 0x46:
            case 0x47:
            case 0x4a:
            case 0x4b:
            case 0x98:
            case 0x99:
            case 0x90:
            case 0x91:
            case 0x92:
            case 0x93:
                return 1;
            default:
                return 0;
        }
    }
    return map_select == 3
        && opcode >= UINT8_C(0x30) && opcode <= UINT8_C(0x33);
}

static const x86_vex_kmask_descriptor *find_vex_kmask_descriptor(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w,
    uint8_t length,
    cdisasm_mode mode)
{
    size_t index;

    for (index = 0;
         index < sizeof(x86_vex_kmask_map) / sizeof(x86_vex_kmask_map[0]);
         ++index) {
        const x86_vex_kmask_descriptor *descriptor =
            &x86_vex_kmask_map[index];

        if (descriptor->map == map_select
            && descriptor->opcode == opcode
            && descriptor->prefix == prefix
            && descriptor->w == w
            && descriptor->length == length
            && ((descriptor->flags & X86_VEX_KMASK_FLAG_MODE64) == 0
                || mode == CDISASM_MODE_64)
            && ((descriptor->flags & X86_VEX_KMASK_FLAG_NOT64) == 0
                || mode != CDISASM_MODE_64)) {
            return descriptor;
        }
    }
    return NULL;
}

static int decode_vex_kmask(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = two_byte
        ? UINT8_C(0)
        : (uint8_t)((vex >> 7) & UINT8_C(1));
    const uint8_t length = (vex >> 2) & UINT8_C(1);
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const int has_immediate = map_select == 3;
    const x86_vex_kmask_descriptor *descriptor;
    x86_modrm modrm;
    uint64_t immediate = 0;

    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* AVX-512 K forms ignore VEX.B outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (has_immediate
        && !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    descriptor = find_vex_kmask_descriptor(
        map_select, opcode, prefix, w, length, decoder->mode);
    if (descriptor == NULL) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    /* K registers have only three encoded bits.  VEX.B/VEX.X are ignored
     * for Mod=3 mask operands, while VEX.R is reserved unless opcode 93
     * uses REG as a GPR.  Opcode 92 likewise applies B to its GPR source. */
    if (descriptor->form == X86_VEX_KMASK_MOVE_GPR_K) {
        if (decoder->mode != CDISASM_MODE_64 && modrm.reg >= 8) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else if (modrm.reg != modrm.reg3) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (modrm.is_register
        && descriptor->form == X86_VEX_KMASK_MOVE_K_GPR
        && decoder->mode != CDISASM_MODE_64 && modrm.rm >= 8) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!modrm.is_register
        && !vex_non64_extensions_are_valid(
            decoder, &modrm, source_index)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (descriptor->form == X86_VEX_KMASK_TERNARY
        || descriptor->form == X86_VEX_KMASK_UNPACK) {
        if (!modrm.is_register || source_index >= 8) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else if (source_index != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((descriptor->form == X86_VEX_KMASK_UNARY
            || descriptor->form == X86_VEX_KMASK_TEST
            || descriptor->form == X86_VEX_KMASK_SHIFT
            || descriptor->form == X86_VEX_KMASK_MOVE_K_GPR
            || descriptor->form == X86_VEX_KMASK_MOVE_GPR_K)
        && !modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (descriptor->form == X86_VEX_KMASK_MOVE_RM_K
        && modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = descriptor->name_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_kmask_foundation(decoder, descriptor->feature_group);

    switch ((x86_vex_kmask_form)descriptor->form) {
        case X86_VEX_KMASK_TERNARY:
            return add_mask_register_operand_access(
                    decoder, modrm.reg, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_mask_register_operand_access(
                    decoder, source_index, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_mask_register_operand_access(
                    decoder, modrm.rm3, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_VEX_KMASK_UNPACK:
            return add_mask_register_operand_access(
                    decoder, modrm.reg, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_mask_register_operand_access(
                    decoder, source_index, descriptor->bits / 2u,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_mask_register_operand_access(
                    decoder, modrm.rm3, descriptor->bits / 2u,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_VEX_KMASK_UNARY:
            return add_mask_register_operand_access(
                    decoder, modrm.reg, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_mask_register_operand_access(
                    decoder, modrm.rm3, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_VEX_KMASK_TEST:
            return add_mask_register_operand_access(
                    decoder, modrm.reg, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_mask_register_operand_access(
                    decoder, modrm.rm3, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_VEX_KMASK_MOVE_K_RM:
            if (!add_mask_register_operand_access(
                    decoder, modrm.reg, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_WRITE)) {
                return 0;
            }
            if (modrm.is_register) {
                return add_mask_register_operand_access(
                    decoder, modrm.rm3, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_READ);
            }
            return add_rm_operand(decoder, &modrm, descriptor->bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);

        case X86_VEX_KMASK_MOVE_RM_K:
            return add_rm_operand(decoder, &modrm, descriptor->bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_WRITE)
                && add_mask_register_operand_access(
                    decoder, modrm.reg, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_VEX_KMASK_MOVE_K_GPR:
            return add_mask_register_operand_access(
                    decoder, modrm.reg, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_register_operand_access(
                    decoder, modrm.rm,
                    descriptor->bits == 64 ? 64u : 32u,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_VEX_KMASK_MOVE_GPR_K:
            return add_register_operand_access(
                    decoder, modrm.reg,
                    descriptor->bits == 64 ? 64u : 32u,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_mask_register_operand_access(
                    decoder, modrm.rm3, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_VEX_KMASK_SHIFT:
            return add_mask_register_operand_access(
                    decoder, modrm.reg, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_mask_register_operand_access(
                    decoder, modrm.rm3, descriptor->bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_immediate_value(decoder, 8u, immediate, 0);

        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
#endif
}

static int modern_vex_structural_form(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix)
{
    if (map_select == 2) {
        if (prefix == X86_SIMD_PREFIX_PF2) {
            if (opcode == UINT8_C(0xcb)) {
                return X86_MODERN_VEX_SHA512_RNDS2;
            }
            if (opcode == UINT8_C(0xcc)) {
                return X86_MODERN_VEX_SHA512_MSG1;
            }
            if (opcode == UINT8_C(0xcd)) {
                return X86_MODERN_VEX_SHA512_MSG2;
            }
        }
        if (opcode == UINT8_C(0xda)) {
            if (prefix == X86_SIMD_PREFIX_NONE
                || prefix == X86_SIMD_PREFIX_P66) {
                return X86_MODERN_VEX_SM3_VECTOR;
            }
            if (prefix == X86_SIMD_PREFIX_PF2
                || prefix == X86_SIMD_PREFIX_PF3) {
                return X86_MODERN_VEX_SM4_VECTOR;
            }
        }
        if ((opcode == UINT8_C(0x00)
                || (opcode >= UINT8_C(0xdc) && opcode <= UINT8_C(0xdf)))
            && prefix == X86_SIMD_PREFIX_P66) {
            return X86_MODERN_VEX_NDS_VECTOR;
        }
        if ((opcode == UINT8_C(0x50) || opcode == UINT8_C(0x51))
            || ((opcode == UINT8_C(0x52) || opcode == UINT8_C(0x53))
                && prefix == X86_SIMD_PREFIX_P66)) {
            return X86_MODERN_VEX_ACCUM_VECTOR;
        }
        if ((opcode == UINT8_C(0xd2) || opcode == UINT8_C(0xd3))
            && (prefix == X86_SIMD_PREFIX_NONE
                || prefix == X86_SIMD_PREFIX_P66
                || prefix == X86_SIMD_PREFIX_PF3)) {
            return X86_MODERN_VEX_ACCUM_VECTOR;
        }
        if (opcode == UINT8_C(0xdb)
            && prefix == X86_SIMD_PREFIX_P66) {
            return X86_MODERN_VEX_UNARY_VECTOR;
        }
        if (opcode == UINT8_C(0x49)) {
            if (prefix == X86_SIMD_PREFIX_NONE) {
                return X86_MODERN_VEX_AMX_CFG_LOAD;
            }
            if (prefix == X86_SIMD_PREFIX_P66) {
                return X86_MODERN_VEX_AMX_CFG_STORE;
            }
            if (prefix == X86_SIMD_PREFIX_PF2) {
                return X86_MODERN_VEX_AMX_ZERO;
            }
        }
        if (opcode == UINT8_C(0x4b)) {
            if (prefix == X86_SIMD_PREFIX_PF2
                || prefix == X86_SIMD_PREFIX_P66) {
                return X86_MODERN_VEX_AMX_LOAD;
            }
            if (prefix == X86_SIMD_PREFIX_PF3) {
                return X86_MODERN_VEX_AMX_STORE;
            }
        }
        if (opcode == UINT8_C(0x4a)
            && (prefix == X86_SIMD_PREFIX_PF2
                || prefix == X86_SIMD_PREFIX_P66)) {
            return X86_MODERN_VEX_AMX_LOAD;
        }
        if (opcode == UINT8_C(0x5c)
            && (prefix == X86_SIMD_PREFIX_PF2
                || prefix == X86_SIMD_PREFIX_PF3)) {
            return X86_MODERN_VEX_AMX_DOT;
        }
        if (opcode == UINT8_C(0x5e)) {
            return X86_MODERN_VEX_AMX_DOT;
        }
        if (opcode == UINT8_C(0x6c)
            && (prefix == X86_SIMD_PREFIX_NONE
                || prefix == X86_SIMD_PREFIX_P66)) {
            return X86_MODERN_VEX_AMX_DOT;
        }
        if (opcode == UINT8_C(0xf2) && prefix == X86_SIMD_PREFIX_NONE) {
            return X86_MODERN_VEX_GPR_R_N_RM;
        }
        if (opcode == UINT8_C(0xf3) && prefix == X86_SIMD_PREFIX_NONE) {
            return X86_MODERN_VEX_BLS;
        }
        if (opcode == UINT8_C(0xf5)
            && (prefix == X86_SIMD_PREFIX_NONE
                || prefix == X86_SIMD_PREFIX_PF2
                || prefix == X86_SIMD_PREFIX_PF3)) {
            return prefix == X86_SIMD_PREFIX_NONE
                ? X86_MODERN_VEX_GPR_R_RM_N
                : X86_MODERN_VEX_GPR_R_N_RM;
        }
        if (opcode == UINT8_C(0xf6) && prefix == X86_SIMD_PREFIX_PF2) {
            return X86_MODERN_VEX_MULX;
        }
        if (opcode == UINT8_C(0xf7)) {
            if (prefix == X86_SIMD_PREFIX_NONE
                || prefix == X86_SIMD_PREFIX_P66
                || prefix == X86_SIMD_PREFIX_PF2
                || prefix == X86_SIMD_PREFIX_PF3) {
                return X86_MODERN_VEX_GPR_R_RM_N;
            }
        }
        if (opcode == UINT8_C(0x13) && prefix == X86_SIMD_PREFIX_P66) {
            return X86_MODERN_VEX_CVTPH2PS;
        }
        if (prefix == X86_SIMD_PREFIX_P66
            && ((opcode >= UINT8_C(0x96) && opcode <= UINT8_C(0x9f))
                || (opcode >= UINT8_C(0xa6) && opcode <= UINT8_C(0xaf))
                || (opcode >= UINT8_C(0xb6) && opcode <= UINT8_C(0xbf)))) {
            const uint8_t low = opcode & UINT8_C(0x0f);

            return low == UINT8_C(0x09) || low == UINT8_C(0x0b)
                    || low == UINT8_C(0x0d) || low == UINT8_C(0x0f)
                ? X86_MODERN_VEX_FMA3_SCALAR32
                : X86_MODERN_VEX_FMA3_PACKED;
        }
    } else if (map_select == 3) {
        if (opcode == UINT8_C(0xde)
            && prefix == X86_SIMD_PREFIX_P66) {
            return X86_MODERN_VEX_SM3_VECTOR_IMM8;
        }
        if (opcode == UINT8_C(0x48) || opcode == UINT8_C(0x49)) {
            return X86_MODERN_VEX_VPERMIL2;
        }
        if ((opcode == UINT8_C(0x0f) || opcode == UINT8_C(0x44))
            && prefix == X86_SIMD_PREFIX_P66) {
            return X86_MODERN_VEX_NDS_VECTOR_IMM8;
        }
        if (opcode == UINT8_C(0xdf)
            && prefix == X86_SIMD_PREFIX_P66) {
            return X86_MODERN_VEX_UNARY_VECTOR_IMM8;
        }
        if (opcode >= UINT8_C(0x5c) && opcode <= UINT8_C(0x5f)) {
            return X86_MODERN_VEX_FMA4_PACKED;
        }
        if ((opcode >= UINT8_C(0x68) && opcode <= UINT8_C(0x6f))
            || (opcode >= UINT8_C(0x78)
                && opcode <= UINT8_C(0x7f))) {
            if ((opcode & UINT8_C(0x03)) == UINT8_C(0x02)) {
                return X86_MODERN_VEX_FMA4_SCALAR32;
            }
            if ((opcode & UINT8_C(0x03)) == UINT8_C(0x03)) {
                return X86_MODERN_VEX_FMA4_SCALAR64;
            }
            return X86_MODERN_VEX_FMA4_PACKED;
        }
        if (opcode == UINT8_C(0xf0) && prefix == X86_SIMD_PREFIX_PF2) {
            return X86_MODERN_VEX_RORX;
        }
        if (opcode == UINT8_C(0x1d) && prefix == X86_SIMD_PREFIX_P66) {
            return X86_MODERN_VEX_CVTPS2PH;
        }
    } else if (map_select == 5 && opcode == UINT8_C(0xfd)) {
        return X86_MODERN_VEX_AMX_DOT;
    }
    return 0;
}

#if USE_EXTRA_OPCODES
static const x86_modern_vex_descriptor *find_modern_vex_descriptor(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w,
    uint8_t form)
{
    size_t index;

    for (index = 0;
         index < sizeof(x86_modern_vex_map) / sizeof(x86_modern_vex_map[0]);
         ++index) {
        const x86_modern_vex_descriptor *descriptor =
            &x86_modern_vex_map[index];

        if (descriptor->map == map_select
            && descriptor->opcode == opcode
            && descriptor->prefix == prefix
            && (descriptor->w == 2 || descriptor->w == w)
            && descriptor->form == form) {
            return descriptor;
        }
    }
    return NULL;
}
#endif

static int decode_modern_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte,
    int structural_form)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0;
    const unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0
        ? 256u
        : 128u;
    int has_imm8 = structural_form == X86_MODERN_VEX_RORX
        || structural_form == X86_MODERN_VEX_CVTPS2PH
        || structural_form == X86_MODERN_VEX_FMA4_PACKED
        || structural_form == X86_MODERN_VEX_FMA4_SCALAR32
        || structural_form == X86_MODERN_VEX_FMA4_SCALAR64
        || structural_form == X86_MODERN_VEX_NDS_VECTOR_IMM8
        || structural_form == X86_MODERN_VEX_UNARY_VECTOR_IMM8
        || structural_form == X86_MODERN_VEX_VPERMIL2
        || structural_form == X86_MODERN_VEX_SM3_VECTOR_IMM8;
    x86_modrm modrm;
    uint64_t immediate = 0;
#if USE_EXTRA_OPCODES
    const x86_modern_vex_descriptor *descriptor;
    unsigned int gpr_bits;
#endif

    if (structural_form == X86_MODERN_VEX_FMA3_SCALAR32) {
        structural_form = w != 0
            ? X86_MODERN_VEX_FMA3_SCALAR64
            : X86_MODERN_VEX_FMA3_SCALAR32;
    }
    if (structural_form >= X86_MODERN_VEX_FMA4_PACKED
        && structural_form <= X86_MODERN_VEX_FMA4_SCALAR64
        && prefix != X86_SIMD_PREFIX_P66) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (structural_form == X86_MODERN_VEX_VPERMIL2
        && prefix != X86_SIMD_PREFIX_P66) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (decoder->mode != CDISASM_MODE_64 && w != 0
        && structural_form >= X86_MODERN_VEX_GPR_R_N_RM
        && structural_form <= X86_MODERN_VEX_RORX) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((structural_form == X86_MODERN_VEX_GPR_R_N_RM
            || structural_form == X86_MODERN_VEX_GPR_R_RM_N
            || structural_form == X86_MODERN_VEX_BLS
            || structural_form == X86_MODERN_VEX_MULX
            || structural_form == X86_MODERN_VEX_RORX)
        && (vex & UINT8_C(0x04)) != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((structural_form == X86_MODERN_VEX_RORX
            || structural_form == X86_MODERN_VEX_CVTPH2PS
            || structural_form == X86_MODERN_VEX_CVTPS2PH
            || structural_form == X86_MODERN_VEX_UNARY_VECTOR
            || structural_form == X86_MODERN_VEX_UNARY_VECTOR_IMM8)
        && source_index != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (structural_form >= X86_MODERN_VEX_SHA512_MSG1
        && structural_form <= X86_MODERN_VEX_SM4_VECTOR
        && w != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (structural_form == X86_MODERN_VEX_ACCUM_VECTOR && w != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (structural_form >= X86_MODERN_VEX_SHA512_MSG1
        && structural_form <= X86_MODERN_VEX_SHA512_RNDS2) {
        if ((vex & UINT8_C(0x04)) == 0 || !modrm.is_register) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if ((structural_form == X86_MODERN_VEX_SHA512_MSG1
                || structural_form == X86_MODERN_VEX_SHA512_MSG2)
            && source_index != 0) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    if ((structural_form == X86_MODERN_VEX_SM3_VECTOR
            || structural_form == X86_MODERN_VEX_SM3_VECTOR_IMM8)
        && (vex & UINT8_C(0x04)) != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    /* VEX.L is part of the encoding grammar, not optional semantic-table
     * ownership.  Validate the fixed-width unary forms even when extra
     * opcode names have been compiled out so ON and OFF builds classify the
     * same malformed byte stream identically. */
    if ((structural_form == X86_MODERN_VEX_UNARY_VECTOR
            || structural_form == X86_MODERN_VEX_UNARY_VECTOR_IMM8)
        && (vex & UINT8_C(0x04)) != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (structural_form == X86_MODERN_VEX_BLS
        && (modrm.reg != modrm.reg3
            || modrm.reg3 < 1 || modrm.reg3 > 3)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (map_select == 2 && opcode == UINT8_C(0x49)
        && prefix == X86_SIMD_PREFIX_NONE) {
        if (modrm.is_register) {
            if (modrm.reg != 0 || modrm.rm != 0) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            structural_form = X86_MODERN_VEX_AMX_RELEASE;
        } else if (modrm.reg != 0) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    if (structural_form >= X86_MODERN_VEX_AMX_CFG_LOAD
        && structural_form <= X86_MODERN_VEX_AMX_DOT) {
        if (decoder->mode != CDISASM_MODE_64 || w != 0
            || (vex & UINT8_C(0x04)) != 0
            || modrm.reg >= 8) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (structural_form != X86_MODERN_VEX_AMX_DOT
            && source_index != 0) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if ((structural_form == X86_MODERN_VEX_AMX_CFG_LOAD
                || structural_form == X86_MODERN_VEX_AMX_CFG_STORE)
            && modrm.is_register) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if ((structural_form == X86_MODERN_VEX_AMX_LOAD
                || structural_form == X86_MODERN_VEX_AMX_STORE)
            && (modrm.is_register || modrm.rm3 != 4)) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (structural_form == X86_MODERN_VEX_AMX_ZERO
            && (!modrm.is_register || modrm.rm != 0)) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (structural_form == X86_MODERN_VEX_AMX_DOT
            && (!modrm.is_register || modrm.rm >= 8
                || source_index >= 8
                || modrm.reg == modrm.rm
                || modrm.reg == source_index
                || modrm.rm == source_index)) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    if (has_imm8 && !read_immediate_value(decoder, 8, &immediate)) {
        return 0;
    }
#if !USE_EXTRA_OPCODES
    (void)prefix;
    (void)vector_bits;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_modern_vex_descriptor(
        map_select, opcode, prefix, w, (uint8_t)structural_form);
    if (descriptor == NULL) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    structural_form = descriptor->form;
    if (descriptor->length == X86_MODERN_VEX_L_ZERO
        && (vex & UINT8_C(0x04)) != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (descriptor->length == X86_MODERN_VEX_L_ONE
        && (vex & UINT8_C(0x04)) == 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->name_id = descriptor->name_id;
    if (structural_form == X86_MODERN_VEX_BLS) {
        static const cdisasm_x86_name_id bls_names[3] = {
            CDISASM_X86_NAME_BLSR,
            CDISASM_X86_NAME_BLSMSK,
            CDISASM_X86_NAME_BLSI
        };
        decoder->name_id = bls_names[modrm.reg3 - 1];
    }
    if (!(structural_form >= X86_MODERN_VEX_AMX_CFG_LOAD
            && structural_form <= X86_MODERN_VEX_AMX_DOT)) {
        decoder_require_caps(decoder, X86_CAP_AVX);
    }
    if (descriptor->feature_group == CDISASM_X86_GROUP_SSSE3) {
        decoder_require_caps(decoder, X86_CAP_SSSE3);
        if (vector_bits == 256u) {
            decoder_require_caps(decoder, X86_CAP_AVX2);
        }
    } else if (descriptor->feature_group == CDISASM_X86_GROUP_VAES
        && vector_bits == 128u) {
        /* The VEX.128 AES forms are the AVX spellings of AES-NI and predate
         * CPUID.VAES.  CPUID.VAES is required only when VEX.L selects 256
         * bits (and for EVEX VAES, handled by the EVEX decoder). */
        decoder_require_extra_any(
            decoder,
            CDISASM_X86_GROUP_AESNI,
            CDISASM_X86_GROUP_VAES);
    } else if (descriptor->feature_group
            == CDISASM_X86_GROUP_VPCLMULQDQ
        && vector_bits == 128u) {
        /* As above, VEX.128 VPCLMULQDQ belongs to PCLMULQDQ+AVX; the
         * VPCLMULQDQ feature bit gates the 256-bit and EVEX forms. */
        decoder_require_extra_any(
            decoder,
            CDISASM_X86_GROUP_PCLMULQDQ,
            CDISASM_X86_GROUP_VPCLMULQDQ);
    } else {
        decoder_require_extra(decoder, descriptor->feature_group);
    }
    if (structural_form >= X86_MODERN_VEX_AMX_CFG_LOAD
        && structural_form <= X86_MODERN_VEX_AMX_DOT
        && descriptor->feature_group != CDISASM_X86_GROUP_AMX_TILE) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AMX_TILE);
    }
    gpr_bits = w != 0 ? 64u : 32u;

    switch ((x86_modern_vex_form)structural_form) {
        case X86_MODERN_VEX_GPR_R_N_RM:
            return add_register_operand_access(
                    decoder, modrm.reg, gpr_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_register_operand_access(
                    decoder, source_index, gpr_bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_rm_operand(decoder, &modrm, gpr_bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_GPR_R_RM_N:
            return add_register_operand_access(
                    decoder, modrm.reg, gpr_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_rm_operand(decoder, &modrm, gpr_bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ)
                && add_register_operand_access(
                    decoder, source_index, gpr_bits,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_BLS:
            return add_register_operand_access(
                    decoder, source_index, gpr_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_rm_operand(decoder, &modrm, gpr_bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_MULX: {
            return add_register_operand_access(
                    decoder, modrm.reg, gpr_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_register_operand_access(
                    decoder, source_index, gpr_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_rm_operand(decoder, &modrm, gpr_bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);
        }

        case X86_MODERN_VEX_RORX:
            return add_register_operand_access(
                    decoder, modrm.reg, gpr_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_rm_operand(decoder, &modrm, gpr_bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ)
                && add_immediate_value(decoder, 8, immediate, 0);

        case X86_MODERN_VEX_CVTPH2PS:
            return add_vector_register_operand_access(
                    decoder, modrm.reg, vector_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_vector_rm_operand_access(
                    decoder, &modrm, 128u, vector_bits / 2u,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_CVTPS2PH:
            return add_vector_rm_operand_access(
                    decoder, &modrm, 128u, vector_bits / 2u,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_vector_register_operand_access(
                    decoder, modrm.reg, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_immediate_value(decoder, 8, immediate, 0);

        case X86_MODERN_VEX_FMA3_PACKED:
        case X86_MODERN_VEX_ACCUM_VECTOR:
            return add_vector_register_operand_access(
                    decoder, modrm.reg, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_vector_register_operand_access(
                    decoder, source_index, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_vector_rm_operand_access(
                    decoder, &modrm, vector_bits, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_FMA3_SCALAR32:
        case X86_MODERN_VEX_FMA3_SCALAR64:
            return add_vector_register_operand_access(
                    decoder, modrm.reg, 128u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_vector_register_operand_access(
                    decoder, source_index, 128u,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_vector_rm_operand_access(
                    decoder, &modrm, 128u,
                    structural_form == X86_MODERN_VEX_FMA3_SCALAR32
                        ? 32u : 64u,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_FMA4_PACKED:
        case X86_MODERN_VEX_FMA4_SCALAR32:
        case X86_MODERN_VEX_FMA4_SCALAR64: {
            unsigned int register_bits =
                structural_form == X86_MODERN_VEX_FMA4_PACKED
                    ? vector_bits : 128u;
            unsigned int memory_bits =
                structural_form == X86_MODERN_VEX_FMA4_SCALAR32
                    ? 32u
                    : (structural_form == X86_MODERN_VEX_FMA4_SCALAR64
                        ? 64u : vector_bits);
            unsigned int immediate_reg = (unsigned int)(immediate >> 4)
                & (decoder->mode == CDISASM_MODE_64 ? 15u : 7u);

            if (!add_vector_register_operand_access(
                    decoder, modrm.reg, register_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                || !add_vector_register_operand_access(
                    decoder, source_index, register_bits,
                    CDISASM_OPERAND_ACCESS_READ)) {
                return 0;
            }
            if (w == 0) {
                return add_vector_rm_operand_access(
                        decoder, &modrm, register_bits, memory_bits,
                        CDISASM_OPERAND_ACCESS_READ)
                    && add_vector_register_operand_access(
                        decoder, immediate_reg, register_bits,
                        CDISASM_OPERAND_ACCESS_READ);
            }
            return add_vector_register_operand_access(
                    decoder, immediate_reg, register_bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_vector_rm_operand_access(
                    decoder, &modrm, register_bits, memory_bits,
                    CDISASM_OPERAND_ACCESS_READ);
        }

        case X86_MODERN_VEX_VPERMIL2: {
            const unsigned int immediate_reg =
                (unsigned int)(immediate >> 4)
                & (decoder->mode == CDISASM_MODE_64 ? 15u : 7u);

            if (!add_vector_register_operand_access(
                    decoder, modrm.reg, vector_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                || !add_vector_register_operand_access(
                    decoder, source_index, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)) {
                return 0;
            }
            if (w == 0) {
                if (!add_vector_rm_operand_access(
                        decoder, &modrm, vector_bits, vector_bits,
                        CDISASM_OPERAND_ACCESS_READ)
                    || !add_vector_register_operand_access(
                        decoder, immediate_reg, vector_bits,
                        CDISASM_OPERAND_ACCESS_READ)) {
                    return 0;
                }
            } else if (!add_vector_register_operand_access(
                    decoder, immediate_reg, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)
                || !add_vector_rm_operand_access(
                    decoder, &modrm, vector_bits, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)) {
                return 0;
            }
            return add_immediate_value(decoder, 8, immediate, 0);
        }

        case X86_MODERN_VEX_NDS_VECTOR:
        case X86_MODERN_VEX_NDS_VECTOR_IMM8:
            if (!add_vector_register_operand_access(
                    decoder, modrm.reg, vector_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                || !add_vector_register_operand_access(
                    decoder, source_index, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)
                || !add_vector_rm_operand_access(
                    decoder, &modrm, vector_bits, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)) {
                return 0;
            }
            return structural_form == X86_MODERN_VEX_NDS_VECTOR
                || add_immediate_value(decoder, 8, immediate, 0);

        case X86_MODERN_VEX_UNARY_VECTOR:
        case X86_MODERN_VEX_UNARY_VECTOR_IMM8:
            if (!add_vector_register_operand_access(
                    decoder, modrm.reg, vector_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                || !add_vector_rm_operand_access(
                    decoder, &modrm, vector_bits, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)) {
                return 0;
            }
            return structural_form == X86_MODERN_VEX_UNARY_VECTOR
                || add_immediate_value(decoder, 8, immediate, 0);

        case X86_MODERN_VEX_SHA512_MSG1:
            return add_vector_register_operand_access(
                    decoder, modrm.reg, 256u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_vector_rm_operand_access(
                    decoder, &modrm, 128u, 128u,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_SHA512_MSG2:
            return add_vector_register_operand_access(
                    decoder, modrm.reg, 256u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_vector_rm_operand_access(
                    decoder, &modrm, 256u, 256u,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_SHA512_RNDS2:
            return add_vector_register_operand_access(
                    decoder, modrm.reg, 256u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_vector_register_operand_access(
                    decoder, source_index, 256u,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_vector_rm_operand_access(
                    decoder, &modrm, 128u, 128u,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_SM3_VECTOR:
        case X86_MODERN_VEX_SM3_VECTOR_IMM8:
            if (!add_vector_register_operand_access(
                    decoder, modrm.reg, 128u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                || !add_vector_register_operand_access(
                    decoder, source_index, 128u,
                    CDISASM_OPERAND_ACCESS_READ)
                || !add_vector_rm_operand_access(
                    decoder, &modrm, 128u, 128u,
                    CDISASM_OPERAND_ACCESS_READ)) {
                return 0;
            }
            return structural_form == X86_MODERN_VEX_SM3_VECTOR
                || add_immediate_value(decoder, 8u, immediate, 0);

        case X86_MODERN_VEX_SM4_VECTOR:
            return add_vector_register_operand_access(
                    decoder, modrm.reg, vector_bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_vector_register_operand_access(
                    decoder, source_index, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_vector_rm_operand_access(
                    decoder, &modrm, vector_bits, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_AMX_CFG_LOAD:
        case X86_MODERN_VEX_AMX_CFG_STORE:
            if (!add_rm_operand(decoder, &modrm, 512u, 0)) {
                return 0;
            }
            decoder->operand[decoder->operand_count - 1].flags |=
                CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
            return set_last_operand_access(
                decoder,
                structural_form == X86_MODERN_VEX_AMX_CFG_LOAD
                    ? CDISASM_OPERAND_ACCESS_READ
                    : CDISASM_OPERAND_ACCESS_WRITE);

        case X86_MODERN_VEX_AMX_LOAD:
            if (!add_tile_register_operand_access(
                    decoder, modrm.reg, CDISASM_OPERAND_ACCESS_WRITE)
                || !add_rm_operand(decoder, &modrm, 8u, 0)) {
                return 0;
            }
            decoder->operand[decoder->operand_count - 1].flags |=
                CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
            return set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_AMX_STORE:
            if (!add_rm_operand(decoder, &modrm, 8u, 0)) {
                return 0;
            }
            decoder->operand[decoder->operand_count - 1].flags |=
                CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
            return set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_WRITE)
                && add_tile_register_operand_access(
                    decoder, modrm.reg, CDISASM_OPERAND_ACCESS_READ);

        case X86_MODERN_VEX_AMX_ZERO:
            return add_tile_register_operand_access(
                decoder, modrm.reg, CDISASM_OPERAND_ACCESS_WRITE);

        case X86_MODERN_VEX_AMX_RELEASE:
            return 1;

        case X86_MODERN_VEX_AMX_DOT:
            return add_tile_register_operand_access(
                    decoder, modrm.reg,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_tile_register_operand_access(
                    decoder, modrm.rm, CDISASM_OPERAND_ACCESS_READ)
                && add_tile_register_operand_access(
                    decoder, source_index, CDISASM_OPERAND_ACCESS_READ);

        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
#endif
}

static int decode_non_temporal_aligned_load_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0 ? 256u : 128u;
    const uint64_t capability = vector_bits == 256u
        ? X86_CAP_AVX2 : X86_CAP_AVX;
    const cdisasm_x86_form_id form_id = vector_bits == 256u
        ? UINT16_C(5866) : UINT16_C(5864);
    x86_modrm modrm;

    if (map_select != UINT8_C(2) || opcode != UINT8_C(0x2a)) {
        return -1;
    }

    /* VMOVNTDQA is the complete VEX map-2/2A pp66 row.  Consume its
     * effective address before classifying reserved pp/vvvv/register forms
     * so malformed short addresses retain TRUNCATED precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66 || source_index != 0
        || modrm.is_register) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decoder_has_caps(decoder, X86_CAP_AVX | capability)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_VMOVNTDQA;
    decoder->form_id = form_id;
    /* Every VEX form carries the AVX encoding foundation; VL256 additionally
     * publishes the exact AVX2 functional family. */
    decoder_require_caps(decoder, X86_CAP_AVX | capability);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vector_move_mask_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0 ? 256u : 128u;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1) || opcode != UINT8_C(0x50)) {
        return -1;
    }

    /* VMOVMSKPD/VMOVMSKPS jointly own the complete VEX map-1/50 row.
     * NP/66 and VL select the four forms, raw vvvv must be 1111, W is
     * ignored, and the source is register-only.  Decode a possible memory
     * effective address before rejecting it so short owned encodings retain
     * TRUNCATED precedence over their final register-only classification. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* VEX.B is ignored by the register-only source in 16/32-bit mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || (prefix != X86_SIMD_PREFIX_NONE
            && prefix != X86_SIMD_PREFIX_P66)
        || source_index != 0 || !modrm.is_register) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decoder_has_caps(decoder, X86_CAP_AVX)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (prefix == X86_SIMD_PREFIX_P66) {
        name_id = CDISASM_X86_NAME_VMOVMSKPD;
        form_id = vector_bits == 128u
            ? UINT16_C(5860) : UINT16_C(5861);
    } else {
        name_id = CDISASM_X86_NAME_VMOVMSKPS;
        form_id = vector_bits == 128u
            ? UINT16_C(5862) : UINT16_C(5863);
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_register_operand_access(
               decoder, modrm.reg, 32u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, modrm.rm, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpmovmskb_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = !two_byte
        && (vex & UINT8_C(0x80)) != 0u;
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0u ? 256u : 128u;
    const uint64_t capability = vector_bits == 256u
        ? X86_CAP_AVX2 : 0u;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(1) || opcode != UINT8_C(0xd7)) {
        return -1;
    }

    /* VPMOVMSKB owns the complete VEX map-1/D7 row.  Decode a possible
     * effective address before rejecting the register-only form so missing
     * SIB/displacement bytes retain payload-first TRUNCATED precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED ignores VEX.B for the register source outside long
         * mode after C4/C5 has been distinguished from LES/LDS. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66 || source_index != 0u
        || !modrm.is_register
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    (void)w;
    (void)capability;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (!decoder_has_caps(decoder, X86_CAP_AVX | capability)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_PMOVMSKB) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = vector_bits == 256u
        ? UINT16_C(7335) : UINT16_C(7334);
    decoder_require_caps(decoder, X86_CAP_AVX | capability);
    return add_register_operand_access(
               decoder, modrm.reg, 32u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, modrm.rm, vector_bits,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vector_duplicate_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0 ? 256u : 128u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x12) && opcode != UINT8_C(0x16))
        || prefix != X86_SIMD_PREFIX_PF3) {
        return -1;
    }

    /* VMOVSLDUP/VMOVSHDUP are fixed-vvvv, WIG unary moves.  XED ignores
     * inverted VEX.B outside long mode, including address forms where its
     * provisional extension would otherwise be hidden.  Consume the full
     * effective address before validating vvvv so truncation wins. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || source_index != 0u
        || !decoder_has_caps(decoder, X86_CAP_AVX)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x16)) {
        form_id = vector_bits == 128u
            ? (modrm.is_register ? UINT16_C(5917) : UINT16_C(5916))
            : (modrm.is_register ? UINT16_C(5923) : UINT16_C(5922));
    } else {
        form_id = vector_bits == 128u
            ? (modrm.is_register ? UINT16_C(5930) : UINT16_C(5929))
            : (modrm.is_register ? UINT16_C(5936) : UINT16_C(5935));
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = opcode == UINT8_C(0x16)
        ? CDISASM_X86_NAME_VMOVSHDUP
        : CDISASM_X86_NAME_VMOVSLDUP;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_unaligned_packed_move_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0 ? 256u : 128u;
    const int is_pd = prefix == X86_SIMD_PREFIX_P66;
    const cdisasm_x86_form_id family_base =
        is_pd ? UINT16_C(5946) : UINT16_C(5963);
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x10) && opcode != UINT8_C(0x11))
        || (prefix != X86_SIMD_PREFIX_NONE
            && prefix != X86_SIMD_PREFIX_P66)) {
        return -1;
    }

    /* VMOVUPD/VMOVUPS jointly own the NP/66 halves of map-1 opcodes 10/11.
     * Both VEX rows are WIG with fixed vvvv and VL selecting XMM/YMM.  XED
     * ignores inverted VEX.B outside long mode.  Consume the full address
     * before the fixed-vvvv split so malformed owned encodings retain
     * TRUNCATED precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || source_index != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (!modrm.is_register) {
        form_id = (cdisasm_x86_form_id)(family_base
            + (opcode == UINT8_C(0x11)
                ? (vector_bits == 128u ? 0u : 4u)
                : (vector_bits == 128u ? 5u : 12u)));
    } else {
        form_id = (cdisasm_x86_form_id)(family_base
            + (opcode == UINT8_C(0x10)
                ? (vector_bits == 128u ? 6u : 13u)
                : (vector_bits == 128u ? 7u : 14u)));
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (!decoder_has_caps(decoder, X86_CAP_AVX)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->name_id = is_pd
        ? CDISASM_X86_NAME_VMOVUPD : CDISASM_X86_NAME_VMOVUPS;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (opcode == UINT8_C(0x10)) {
        return add_vector_register_operand_access(
                   decoder, modrm.reg, vector_bits,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_rm_operand_access(
                   decoder, &modrm, vector_bits, vector_bits,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vector_move_scalar_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int encoded_source =
        ((unsigned int)(~vex) >> 3) & 15u;
    unsigned int source_index = encoded_source;
    const int is_double = prefix == X86_SIMD_PREFIX_PF2;
    const unsigned int memory_bits = is_double ? 64u : 32u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x10) && opcode != UINT8_C(0x11))
        || (!is_double && prefix != X86_SIMD_PREFIX_PF3)) {
        return -1;
    }

    /* Both VEX scalar-move opcodes are LIG/WIG.  Consume a complete ModRM
     * address before validating the fixed-vvvv memory selector so a missing
     * SIB/displacement retains TRUNCATED precedence.  Outside long mode B
     * and the NDS high bit are ignored by pinned XED. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(
            decoder, &modrm, source_index)
        || (!modrm.is_register && encoded_source != 0u)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decoder_has_caps(decoder, X86_CAP_AVX)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (is_double) {
        form_id = modrm.is_register
            ? (opcode == UINT8_C(0x10)
                ? UINT16_C(5912) : UINT16_C(5913))
            : (opcode == UINT8_C(0x10)
                ? UINT16_C(5911) : UINT16_C(5910));
    } else {
        form_id = modrm.is_register
            ? (opcode == UINT8_C(0x10)
                ? UINT16_C(5942) : UINT16_C(5943))
            : (opcode == UINT8_C(0x10)
                ? UINT16_C(5941) : UINT16_C(5939));
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)memory_bits;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = is_double
        ? CDISASM_X86_NAME_VMOVSD : CDISASM_X86_NAME_VMOVSS;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);

    if (!modrm.is_register) {
        if (opcode == UINT8_C(0x10)) {
            return add_vector_register_operand_access(
                       decoder, modrm.reg, 128u,
                       CDISASM_OPERAND_ACCESS_WRITE)
                && add_vector_rm_operand_access(
                       decoder, &modrm, 128u, memory_bits,
                       CDISASM_OPERAND_ACCESS_READ);
        }
        return add_vector_rm_operand_access(
                   decoder, &modrm, 128u, memory_bits,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                   decoder, modrm.reg, 128u,
                   CDISASM_OPERAND_ACCESS_READ);
    }

    if (opcode == UINT8_C(0x10)) {
        return add_vector_register_operand_access(
                   decoder, modrm.reg, 128u,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                   decoder, source_index, 128u,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_vector_register_operand_access(
                   decoder, modrm.rm, 128u,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_register_operand_access(
               decoder, modrm.rm, 128u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, source_index, 128u,
               CDISASM_OPERAND_ACCESS_READ)
        && add_vector_register_operand_access(
               decoder, modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vector_move_quadword_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = !two_byte
        && (vex & UINT8_C(0x80)) != 0;
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const int is_66 = prefix == X86_SIMD_PREFIX_P66;
    const int is_f3 = prefix == X86_SIMD_PREFIX_PF3;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x6e)
            && opcode != UINT8_C(0x7e)
            && opcode != UINT8_C(0xd6))) {
        return -1;
    }

    /* VMOVD and VMOVQ jointly occupy these three VEX map-1 rows.  Decode a
     * complete effective address before the selector split so malformed
     * SIB/displacement payloads retain TRUNCATED precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64
        && vex_vmovdq_non64_b_is_ignored(
            map_select, opcode, vex)) {
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || source_index != 0
        || (vex & UINT8_C(0x04)) != 0
        || (opcode == UINT8_C(0x6e) && !is_66)
        || (opcode == UINT8_C(0x7e) && !is_66 && !is_f3)
        || (opcode == UINT8_C(0xd6) && !is_66)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    /* W0 is VMOVD in long mode, while W is ignored for VMOVD outside long
     * mode.  Apply that generated form's AVX profile gate before delegating:
     * the wrapper deliberately preserves this core INVALID result when the
     * generated decoder rejects the same bytes solely for the selected CPU. */
    if (!decoder_has_caps(decoder, X86_CAP_AVX)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((opcode == UINT8_C(0x6e)
            || (opcode == UINT8_C(0x7e) && is_66))
        && (decoder->mode != CDISASM_MODE_64 || w == 0)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x6e)) {
        form_id = modrm.is_register
            ? UINT16_C(5889) : UINT16_C(5890);
    } else if (opcode == UINT8_C(0x7e) && is_66) {
        form_id = modrm.is_register
            ? UINT16_C(5884) : UINT16_C(5886);
    } else if (opcode == UINT8_C(0x7e)) {
        form_id = modrm.is_register
            ? UINT16_C(5892) : UINT16_C(5891);
    } else {
        form_id = modrm.is_register
            ? UINT16_C(5893) : UINT16_C(5887);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_VMOVQ;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);

    if (opcode == UINT8_C(0x6e)) {
        if (!add_vector_register_operand_access(
                decoder, modrm.reg, 128u,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (modrm.is_register) {
            return add_register_operand_access(
                decoder, modrm.rm, 64u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, 64u, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    if (opcode == UINT8_C(0x7e) && is_66) {
        if (modrm.is_register) {
            if (!add_register_operand_access(
                    decoder, modrm.rm, 64u,
                    CDISASM_OPERAND_ACCESS_WRITE)) {
                return 0;
            }
        } else if (!add_rm_operand(decoder, &modrm, 64u, 1)
            || !set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        return add_vector_register_operand_access(
            decoder, modrm.reg, 128u,
            CDISASM_OPERAND_ACCESS_READ);
    }
    if (opcode == UINT8_C(0x7e)) {
        return add_vector_register_operand_access(
                   decoder, modrm.reg, 128u,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_rm_operand_access(
                   decoder, &modrm, 128u, 64u,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_rm_operand_access(
               decoder, &modrm, 128u, 64u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_unaligned_integer_load_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0 ? 256u : 128u;
    const cdisasm_x86_form_id form_id = vector_bits == 256u
        ? UINT16_C(5584) : UINT16_C(5583);
    x86_modrm modrm;

    if (map_select != UINT8_C(1) || opcode != UINT8_C(0xf0)) {
        return -1;
    }

    /* VLDDQU is the complete VEX map-1/F0 row.  Its pp field is F2, vvvv
     * is fixed to raw 1111, W is ignored, and both vector lengths belong
     * to AVX.  Consume the complete effective address before classifying
     * reserved selectors so truncated SIB/displacement data wins. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_PF2 || source_index != 0
        || modrm.is_register) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decoder_has_caps(decoder, X86_CAP_AVX)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_VLDDQU;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_non_temporal_vector_store_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0 ? 256u : 128u;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x2b) && opcode != UINT8_C(0xe7))) {
        return -1;
    }

    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (source_index != 0 || modrm.is_register
        || (opcode == UINT8_C(0xe7)
            && prefix != X86_SIMD_PREFIX_P66)
        || (opcode == UINT8_C(0x2b)
            && prefix != X86_SIMD_PREFIX_NONE
            && prefix != X86_SIMD_PREFIX_P66)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decoder_has_caps(decoder, X86_CAP_AVX)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0xe7)) {
        name_id = CDISASM_X86_NAME_VMOVNTDQ;
        form_id = vector_bits == 128u
            ? UINT16_C(5869) : UINT16_C(5870);
    } else if (prefix == X86_SIMD_PREFIX_P66) {
        name_id = CDISASM_X86_NAME_VMOVNTPD;
        form_id = vector_bits == 128u
            ? UINT16_C(5874) : UINT16_C(5878);
    } else {
        name_id = CDISASM_X86_NAME_VMOVNTPS;
        form_id = vector_bits == 128u
            ? UINT16_C(5879) : UINT16_C(5883);
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpblend_vdpp_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const int is_selector = opcode == UINT8_C(0x4a)
        || opcode == UINT8_C(0x4b) || opcode == UINT8_C(0x4c);
    const int is_fp_selector = opcode == UINT8_C(0x4a)
        || opcode == UINT8_C(0x4b);
    const int is_fp_blend = opcode == UINT8_C(0x0c)
        || opcode == UINT8_C(0x0d);
    const int is_dot_product = opcode == UINT8_C(0x40)
        || opcode == UINT8_C(0x41);
    const int is_fp_family = is_fp_blend || is_fp_selector
        || is_dot_product;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0u ? 256u : 128u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(3)
        || (opcode != UINT8_C(0x02) && opcode != UINT8_C(0x0c)
            && opcode != UINT8_C(0x0d) && opcode != UINT8_C(0x0e)
            && opcode != UINT8_C(0x40) && opcode != UINT8_C(0x41)
            && opcode != UINT8_C(0x4a) && opcode != UINT8_C(0x4b)
            && opcode != UINT8_C(0x4c))) {
        return -1;
    }

    /* All nine complete map-3 rows own ModRM/addressing plus their trailing
     * byte.  Consume the payload before rejecting pp/W or a legacy prefix so
     * incomplete owned encodings retain TRUNCATED precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* VEX.B and the high vvvv bit are ignored outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(1);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (is_selector) {
        uint8_t selector;

        decoder->encoding.selector_offset = (uint8_t)decoder->position;
        if (!read_u8(decoder, &selector)) {
            return 0;
        }
        immediate = selector;
    } else if (!read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66
        || ((opcode == UINT8_C(0x02) || is_selector) && w != 0u)
        || (opcode == UINT8_C(0x41) && vector_bits != 128u)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = (cdisasm_x86_form_id)(
        (opcode == UINT8_C(0x02) ? UINT16_C(6306)
            : opcode == UINT8_C(0x0c) ? UINT16_C(3531)
            : opcode == UINT8_C(0x0d) ? UINT16_C(3527)
            : opcode == UINT8_C(0x40) ? UINT16_C(4515)
            : opcode == UINT8_C(0x41) ? UINT16_C(4507)
            : opcode == UINT8_C(0x4a) ? UINT16_C(3539)
            : opcode == UINT8_C(0x4b) ? UINT16_C(3535)
            : is_selector ? UINT16_C(6334) : UINT16_C(6338))
        + (vector_bits == 256u ? 2u : 0u)
        + (modrm.is_register ? 1u : 0u));

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)immediate;
    (void)source_index;
    (void)is_fp_blend;
    (void)is_fp_family;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL
        || descriptor->form != (is_selector
            ? X86_VEX_EXTRA_FORM_PACKED_SELECTOR
            : is_fp_blend || is_dot_product
                ? X86_VEX_EXTRA_FORM_PACKED_FP_IMM8
                : X86_VEX_EXTRA_FORM_PACKED_INTEGER_IMM8)) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (opcode == UINT8_C(0x02)
        || (!is_fp_family && vector_bits == 256u)) {
        decoder_require_caps(decoder, X86_CAP_AVX2);
    }
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)
        || !add_vector_register_operand_access(
               decoder, source_index, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        || !add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (is_selector) {
        const unsigned int selector_index = (unsigned int)(immediate >> 4)
            & (decoder->mode == CDISASM_MODE_64 ? 15u : 7u);

        return add_vector_register_operand_access(
            decoder, selector_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ);
    }
    return add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vmxcsr_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    x86_modrm modrm;

    if (map_select != UINT8_C(1) || opcode != UINT8_C(0xae)) {
        return -1;
    }

    /* VEX.0F.AE owns ModRM and its complete address payload before pp/L,
     * vvvv, or forbidden legacy prefixes are classified.  This preserves
     * TRUNCATED precedence for structurally owned incomplete encodings. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED ignores inverted VEX.B outside long mode.  R/X remain
         * fixed by C4/LES disambiguation, while VEX2 has no B field. */
        decoder->rex &= (uint8_t)~UINT8_C(1);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if ((vex & UINT8_C(0x7f)) != UINT8_C(0x78)
        || source_index != 0u
        || modrm.is_register
        || (modrm.reg3 != 2u && modrm.reg3 != 3u)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = modrm.reg3 == 2u
        ? CDISASM_X86_NAME_VLDMXCSR
        : CDISASM_X86_NAME_VSTMXCSR;
    decoder->form_id = modrm.reg3 == 2u
        ? UINT16_C(5585) : UINT16_C(8752);
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_rm_operand(decoder, &modrm, 32u, 1)
        && set_last_operand_access(decoder, modrm.reg3 == 2u
            ? CDISASM_OPERAND_ACCESS_READ
            : CDISASM_OPERAND_ACCESS_WRITE);
#endif
}

static int decode_vmaskmov_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = two_byte
        ? UINT8_C(0) : (uint8_t)((vex >> 7) & UINT8_C(1));
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0u ? 256u : 128u;
    unsigned int mask_index = ((unsigned int)(~vex) >> 3) & 15u;
    const int store = opcode >= UINT8_C(0x2e);
    const int pd = (opcode & UINT8_C(1)) != 0u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(2)
        || opcode < UINT8_C(0x2c) || opcode > UINT8_C(0x2f)) {
        return -1;
    }

    /* VMASKMOVPS/PD jointly own the complete VEX map-2 2C..2F rows.
     * Decode the complete memory address before rejecting W, pp, ModRM, or
     * encountered legacy-prefix controls so incomplete owned encodings keep
     * payload-first TRUNCATED precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED aliases VEX.B and vvvv[3] to their low-register forms
         * outside long mode once raw R'=X'=1 has selected C4 over LES. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        mask_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, mask_index)
        || prefix != X86_SIMD_PREFIX_P66 || w != 0u
        || modrm.is_register
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x2c)) {
        form_id = vector_bits == 128u
            ? UINT16_C(5593) : UINT16_C(5594);
    } else if (opcode == UINT8_C(0x2d)) {
        form_id = vector_bits == 128u
            ? UINT16_C(5589) : UINT16_C(5590);
    } else if (opcode == UINT8_C(0x2e)) {
        form_id = vector_bits == 128u
            ? UINT16_C(5591) : UINT16_C(5592);
    } else {
        form_id = vector_bits == 128u
            ? UINT16_C(5587) : UINT16_C(5588);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)store;
    (void)pd;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = pd
        ? CDISASM_X86_NAME_VMASKMOVPD
        : CDISASM_X86_NAME_VMASKMOVPS;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (!store) {
        return add_vector_register_operand_access(
                   decoder, modrm.reg, vector_bits,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                   decoder, mask_index, vector_bits,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_vector_rm_operand_access(
                   decoder, &modrm, vector_bits, vector_bits,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, mask_index, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpmaskmov_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (uint8_t)((vex >> 7) & UINT8_C(1));
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0u ? 256u : 128u;
    unsigned int mask_index = ((unsigned int)(~vex) >> 3) & 15u;
    const int load = opcode == UINT8_C(0x8c);
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (two_byte || map_select != UINT8_C(2)
        || (opcode != UINT8_C(0x8c) && opcode != UINT8_C(0x8e))) {
        return -1;
    }

    /* Both VPMASKMOV opcode rows own every pp/W/L/vvvv/ModRM control.  Read
     * the complete effective address before rejecting a reserved prefix or
     * register ModRM so incomplete owned encodings remain TRUNCATED. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Once C4 has won over LES, B' and vvvv[3] alias their low forms. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        mask_index &= 7u;
    }
    decoder->rex_present = 0u;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, mask_index)
        || prefix != X86_SIMD_PREFIX_P66 || modrm.is_register
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (load) {
        form_id = (cdisasm_x86_form_id)(
            (w != 0u ? UINT16_C(7158) : UINT16_C(7154))
            + (vector_bits == 256u ? 1u : 0u));
    } else {
        form_id = (cdisasm_x86_form_id)(
            (w != 0u ? UINT16_C(7156) : UINT16_C(7152))
            + (vector_bits == 256u ? 1u : 0u));
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)vector_bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = w != 0u
        ? CDISASM_X86_NAME_VPMASKMOVQ
        : CDISASM_X86_NAME_VPMASKMOVD;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX2);
    if (load) {
        return add_vector_register_operand_access(
                   decoder, modrm.reg, vector_bits,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                   decoder, mask_index, vector_bits,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_vector_rm_operand_access(
                   decoder, &modrm, vector_bits, vector_bits,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, mask_index, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vmpsadbw_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0u ? 256u : 128u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(3) || opcode != UINT8_C(0x42)) {
        return -1;
    }

    /* The complete VEX.0F3A.42 row carries ModRM plus imm8 even when pp is
     * reserved.  Consume both payloads before selector classification so a
     * missing SIB/displacement/immediate retains TRUNCATED precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* VEX.B and the high vvvv bit are ignored outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(1);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (prefix != X86_SIMD_PREFIX_P66) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (vector_bits == 128u) {
        form_id = modrm.is_register
            ? UINT16_C(5988) : UINT16_C(5987);
    } else {
        form_id = modrm.is_register
            ? UINT16_C(5992) : UINT16_C(5991);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)immediate;
    (void)source_index;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_VMPSADBW;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (vector_bits == 256u) {
        decoder_require_caps(decoder, X86_CAP_AVX2);
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, source_index, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vbroadcast128_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0;
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0 ? 256u : 128u;
    x86_modrm modrm;

    if (two_byte || map_select != UINT8_C(2)
        || (opcode != UINT8_C(0x1a) && opcode != UINT8_C(0x5a))) {
        return -1;
    }

    /* Both opcode rows own ModRM and the complete effective-address payload.
     * Validate the fixed selector only afterward so malformed complete words
     * are INVALID while incomplete owned words retain TRUNCATED precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Raw R'/X'=1 already distinguish C4 from LES; B' is ignored by the
         * architectural eight-register alias outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (w != 0 || vector_bits != 256u
        || prefix != X86_SIMD_PREFIX_P66 || source_index != 0u
        || modrm.is_register || decoder->lock_prefix
        || decoder->repeat_prefix || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = opcode == UINT8_C(0x1a)
        ? CDISASM_X86_NAME_VBROADCASTF128
        : CDISASM_X86_NAME_VBROADCASTI128;
    decoder->form_id = opcode == UINT8_C(0x1a)
        ? UINT16_C(3543) : UINT16_C(3554);
    if (opcode == UINT8_C(0x1a)) {
        decoder_require_caps(decoder, X86_CAP_AVX);
    } else {
        /* AVX is the encoding foundation while AVX2 is this form's exact
         * ISA set and most-specific runtime selector. */
        decoder_require_caps(decoder, X86_CAP_AVX | X86_CAP_AVX2);
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, 256u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_rm_operand(decoder, &modrm, 128u, 1)
        && set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vbroadcast_scalar_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0u ? 256u : 128u;
    const unsigned int scalar_bits = opcode == UINT8_C(0x19)
        ? 64u : 32u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (two_byte || map_select != UINT8_C(2)
        || (opcode != UINT8_C(0x18) && opcode != UINT8_C(0x19))) {
        return -1;
    }

    /* Both opcode rows own ModRM and its complete effective-address payload.
     * Validate the fixed selectors only afterward so malformed complete
     * encodings are INVALID while incomplete owned encodings are TRUNCATED. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Raw R'/X'=1 already distinguish C4 from LES.  B' aliases in the
         * architectural eight-register namespace outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (w != 0u || prefix != X86_SIMD_PREFIX_P66
        || source_index != 0u
        || (opcode == UINT8_C(0x19) && vector_bits != 256u)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x19)) {
        form_id = modrm.is_register
            ? UINT16_C(3570) : UINT16_C(3569);
    } else if (vector_bits == 128u) {
        form_id = modrm.is_register
            ? UINT16_C(3574) : UINT16_C(3573);
    } else {
        form_id = modrm.is_register
            ? UINT16_C(3580) : UINT16_C(3579);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)scalar_bits;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL
        || descriptor->form != (opcode == UINT8_C(0x18)
            ? X86_VEX_EXTRA_FORM_BROADCAST_SCALAR_SINGLE
            : X86_VEX_EXTRA_FORM_BROADCAST_SCALAR_DOUBLE)) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (modrm.is_register) {
        /* AVX is the encoding foundation, while the register-source forms'
         * exact ISA set and most-specific public selector are AVX2. */
        decoder_require_caps(decoder, X86_CAP_AVX2);
    }
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    if (modrm.is_register) {
        return add_named_register_operand_access(
            decoder, xmm_id(modrm.rm), 128u,
            CDISASM_OPERAND_ACCESS_READ);
    }
    return add_rm_operand(decoder, &modrm, scalar_bits, 1)
        && set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpbroadcast_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0;
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0 ? 256u : 128u;
    unsigned int scalar_bits;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (two_byte || map_select != UINT8_C(2)
        || (opcode != UINT8_C(0x58) && opcode != UINT8_C(0x59)
            && opcode != UINT8_C(0x78) && opcode != UINT8_C(0x79))) {
        return -1;
    }

    if (opcode == UINT8_C(0x58)) {
        scalar_bits = 32u;
    } else if (opcode == UINT8_C(0x59)) {
        scalar_bits = 64u;
    } else if (opcode == UINT8_C(0x78)) {
        scalar_bits = 8u;
    } else {
        scalar_bits = 16u;
    }

    /* This opcode row owns ModRM and its complete address payload even when
     * W, pp, vvvv, or an encountered legacy prefix makes the selector
     * reserved.  Preserve TRUNCATED precedence for those malformed rows. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Raw R'/X'=1 are already required to distinguish C4 from LES.
         * B' aliases in the eight-register non-long namespace. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (w != 0 || prefix != X86_SIMD_PREFIX_P66 || source_index != 0
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x58) && vector_bits == 128u) {
        form_id = modrm.is_register
            ? UINT16_C(6356) : UINT16_C(6355);
    } else if (opcode == UINT8_C(0x58)) {
        form_id = modrm.is_register
            ? UINT16_C(6361) : UINT16_C(6360);
    } else if (opcode == UINT8_C(0x59) && vector_bits == 128u) {
        form_id = modrm.is_register
            ? UINT16_C(6375) : UINT16_C(6374);
    } else if (opcode == UINT8_C(0x59)) {
        form_id = modrm.is_register
            ? UINT16_C(6380) : UINT16_C(6379);
    } else if (opcode == UINT8_C(0x78) && vector_bits == 128u) {
        form_id = modrm.is_register
            ? UINT16_C(6343) : UINT16_C(6342);
    } else if (opcode == UINT8_C(0x78)) {
        form_id = modrm.is_register
            ? UINT16_C(6348) : UINT16_C(6347);
    } else if (vector_bits == 128u) {
        form_id = modrm.is_register
            ? UINT16_C(6388) : UINT16_C(6387);
    } else {
        form_id = modrm.is_register
            ? UINT16_C(6393) : UINT16_C(6392);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)scalar_bits;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (opcode == UINT8_C(0x58)) {
        decoder->name_id = CDISASM_X86_NAME_VPBROADCASTD;
    } else if (opcode == UINT8_C(0x59)) {
        decoder->name_id = CDISASM_X86_NAME_VPBROADCASTQ;
    } else {
        decoder->name_id = opcode == UINT8_C(0x78)
            ? CDISASM_X86_NAME_VPBROADCASTB
            : CDISASM_X86_NAME_VPBROADCASTW;
    }
    decoder->form_id = form_id;
    /* AVX is the encoding umbrella and AVX2 is the exact XED ISA_SET.  The
     * public selector chooses the most-specific group, so AVX2 alone admits
     * this family while both groups remain visible in structured output. */
    decoder_require_caps(decoder, X86_CAP_AVX | X86_CAP_AVX2);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    if (modrm.is_register) {
        return add_named_register_operand_access(
            decoder, xmm_id(modrm.rm), scalar_bits,
            CDISASM_OPERAND_ACCESS_READ);
    }
    return add_rm_operand(decoder, &modrm, scalar_bits, 1)
        && set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_lane_insert_extract_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const int is_extract = opcode == UINT8_C(0x19)
        || opcode == UINT8_C(0x39);
    const int is_integer = opcode == UINT8_C(0x38)
        || opcode == UINT8_C(0x39);
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
    unsigned int expected_form;
#endif

    if (two_byte || map_select != UINT8_C(3)
        || (opcode != UINT8_C(0x18) && opcode != UINT8_C(0x19)
            && opcode != UINT8_C(0x38) && opcode != UINT8_C(0x39))) {
        return -1;
    }

    /* These four rows own ModRM/addressing and their imm8 even when pp, W,
     * L, vvvv, or an encountered legacy prefix is reserved.  Consume the
     * complete payload first so an incomplete owned encoding is TRUNCATED. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* VEX.B aliases in the eight-register namespace.  The high logical
         * vvvv bit aliases for insert forms, but remains part of extract's
         * architecturally fixed VEXDEST=0 field. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        if (!is_extract) {
            source_index &= 7u;
        }
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || w != 0u || (vex & UINT8_C(0x04)) == 0u
        || prefix != X86_SIMD_PREFIX_P66
        || (is_extract && source_index != 0u)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = (cdisasm_x86_form_id)(
        (opcode == UINT8_C(0x19) ? UINT16_C(4539)
            : opcode == UINT8_C(0x39) ? UINT16_C(4553)
            : opcode == UINT8_C(0x18) ? UINT16_C(5551)
            : UINT16_C(5565))
        + (modrm.is_register ? 1u : 0u));

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)immediate;
    (void)is_integer;
    (void)source_index;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    expected_form = opcode == UINT8_C(0x19)
        ? X86_VEX_EXTRA_FORM_EXTRACT_F128
        : opcode == UINT8_C(0x39)
            ? X86_VEX_EXTRA_FORM_EXTRACT_I128
            : opcode == UINT8_C(0x18)
                ? X86_VEX_EXTRA_FORM_INSERT_F128
                : X86_VEX_EXTRA_FORM_INSERT_I128;
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL || descriptor->form != expected_form) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (is_integer) {
        decoder_require_caps(decoder, X86_CAP_AVX2);
    }
    if (is_extract) {
        return add_vector_rm_operand_access(
                   decoder, &modrm, 128u, 128u,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                decoder, modrm.reg, 256u,
                CDISASM_OPERAND_ACCESS_READ)
            && add_immediate_value(decoder, 8u, immediate, 0);
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, 256u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, source_index, 256u,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, 128u, 128u,
            CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vextractps_vinsertps_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const int is_extract = opcode == UINT8_C(0x17);
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
    unsigned int expected_form;
#endif

    if (two_byte || map_select != UINT8_C(3)
        || (opcode != UINT8_C(0x17) && opcode != UINT8_C(0x21))) {
        return -1;
    }

    /* These rows own ModRM/addressing and imm8 for every VEX.W, pp, L, and
     * vvvv spelling.  Consume that complete payload before selector policy
     * so malformed incomplete encodings retain TRUNCATED precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* R'/X'=1 distinguish C4 from LES.  B' aliases in the eight-register
         * namespace, as does the high logical vvvv bit for the NDS insert;
         * extract's NOVSR field remains architecturally fixed. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        if (!is_extract) {
            source_index &= 7u;
        }
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || (vex & UINT8_C(0x04)) != 0u
        || prefix != X86_SIMD_PREFIX_P66
        || (is_extract && source_index != 0u)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (is_extract) {
        form_id = modrm.is_register
            ? UINT16_C(4567) : UINT16_C(4569);
    } else {
        form_id = modrm.is_register
            ? UINT16_C(5580) : UINT16_C(5579);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)immediate;
    (void)source_index;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    expected_form = is_extract
        ? X86_VEX_EXTRA_FORM_EXTRACT_PS
        : X86_VEX_EXTRA_FORM_INSERT_PS;
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL || descriptor->form != expected_form) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (is_extract) {
        if (modrm.is_register) {
            if (!add_register_operand_access(
                    decoder, modrm.rm, 32u,
                    CDISASM_OPERAND_ACCESS_WRITE)) {
                return 0;
            }
        } else if (!add_rm_operand(decoder, &modrm, 32u, 1)
            || !set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        return add_vector_register_operand_access(
                   decoder, modrm.reg, 128u,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_immediate_value(decoder, 8u, immediate, 0);
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, source_index, 128u,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, 128u, 32u,
            CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vperm2_128_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const int is_integer = opcode == UINT8_C(0x46);
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
    unsigned int expected_form;
#endif

    if (two_byte || map_select != UINT8_C(3)
        || (opcode != UINT8_C(0x06) && opcode != UINT8_C(0x46))) {
        return -1;
    }

    /* Both opcode rows own ModRM/addressing and imm8 even when a control
     * field or encountered legacy prefix is reserved.  Decode the complete
     * payload before policy so incomplete owned encodings are TRUNCATED. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Raw R'/X'=1 distinguish C4 from LES.  B' and the high NDS vvvv
         * bit alias in the architectural eight-register namespace. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || w != 0u || (vex & UINT8_C(0x04)) == 0u
        || prefix != X86_SIMD_PREFIX_P66
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = (cdisasm_x86_form_id)(
        (is_integer ? UINT16_C(6772) : UINT16_C(6770))
        + (modrm.is_register ? 1u : 0u));

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)immediate;
    (void)is_integer;
    (void)source_index;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    expected_form = is_integer
        ? X86_VEX_EXTRA_FORM_PERM2_I128
        : X86_VEX_EXTRA_FORM_PERM2_F128;
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL || descriptor->form != expected_form) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (is_integer) {
        decoder_require_caps(decoder, X86_CAP_AVX2);
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, 256u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, source_index, 256u,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, 256u, 256u,
            CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vpermd_vpermps_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const int integer = opcode == UINT8_C(0x36);
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
    unsigned int expected_form;
#endif

    if (two_byte || map_select != UINT8_C(2)
        || (opcode != UINT8_C(0x16) && opcode != UINT8_C(0x36))) {
        return -1;
    }

    /* These complete map-2 opcode rows own ModRM/addressing before the
     * fixed pp/W/L policy is applied.  This keeps late SIB/displacement
     * truncation ahead of rejection for malformed owned encodings. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Raw R'/X'=1 distinguish C4 from LES.  B' and the high NDS vvvv
         * bit alias in the architectural eight-register namespace. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || w != 0u || (vex & UINT8_C(0x04)) == 0u
        || prefix != X86_SIMD_PREFIX_P66
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = (cdisasm_x86_form_id)(
        (integer ? UINT16_C(6780) : UINT16_C(6886))
        + (modrm.is_register ? 1u : 0u));

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)integer;
    (void)source_index;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    expected_form = integer
        ? X86_VEX_EXTRA_FORM_PERMD
        : X86_VEX_EXTRA_FORM_PERMPS;
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL || descriptor->form != expected_form) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX | X86_CAP_AVX2);
    return add_vector_register_operand_access(
               decoder, modrm.reg, 256u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, source_index, 256u,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, 256u, 256u,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpermpd_vpermq_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const int floating = opcode == UINT8_C(0x01);
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
    unsigned int expected_form;
#endif

    if (two_byte || map_select != UINT8_C(3)
        || (opcode != UINT8_C(0x00) && opcode != UINT8_C(0x01))) {
        return -1;
    }

    /* These complete map-3 opcode rows own ModRM/addressing and imm8 before
     * fixed pp/W/L/vvvv policy is applied.  Reserved controls therefore do
     * not hide a truncated SIB, displacement, or trailing selector. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Raw R'/X'=1 distinguish C4 from LES; pinned XED treats B' as
         * ignored for these classic AVX2 rows outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, 0u)
        || w != 1u || (vex & UINT8_C(0x7c)) != UINT8_C(0x7c)
        || prefix != X86_SIMD_PREFIX_P66
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = (cdisasm_x86_form_id)(
        (floating ? UINT16_C(6878) : UINT16_C(6890))
        + (modrm.is_register ? 1u : 0u));

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)floating;
    (void)immediate;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    expected_form = floating
        ? X86_VEX_EXTRA_FORM_PERMPD
        : X86_VEX_EXTRA_FORM_PERMQ;
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL || descriptor->form != expected_form) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX | X86_CAP_AVX2);
    return add_vector_register_operand_access(
               decoder, modrm.reg, 256u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
            decoder, &modrm, 256u, 256u,
            CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vpermilpd_vpermilps_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const int immediate_form = map_select == UINT8_C(3);
    const int is_double = opcode == (immediate_form
        ? UINT8_C(0x05) : UINT8_C(0x0d));
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    uint64_t immediate = 0u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
    unsigned int expected_form;
#endif

    if (two_byte
        || !((map_select == UINT8_C(3)
                && (opcode == UINT8_C(0x04)
                    || opcode == UINT8_C(0x05)))
            || (map_select == UINT8_C(2)
                && (opcode == UINT8_C(0x0c)
                    || opcode == UINT8_C(0x0d))))) {
        return -1;
    }

    /* These complete opcode rows own ModRM/addressing and, for map 3, the
     * trailing imm8 before fixed W/pp/vvvv policy is applied. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Raw R'/X'=1 distinguish C4 from LES.  B' is ignored for these
         * rows, and the NDS source aliases into the eight-register file. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        if (!immediate_form) {
            source_index &= 7u;
        }
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || (immediate_form
            && !read_immediate_value(decoder, 8u, &immediate))) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(
            decoder, &modrm, immediate_form ? 0u : source_index)
        || w != 0u || prefix != X86_SIMD_PREFIX_P66
        || (immediate_form
            && (vex & UINT8_C(0x78)) != UINT8_C(0x78))
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = (cdisasm_x86_form_id)(
        (is_double ? UINT16_C(6834) : UINT16_C(6854))
        + (immediate_form ? 0u : 2u)
        + (vector_bits == 256u ? 12u : 0u)
        + (modrm.is_register ? 1u : 0u));

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)is_double;
    (void)vector_bits;
    (void)source_index;
    (void)immediate;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    expected_form = immediate_form
        ? X86_VEX_EXTRA_FORM_PERMIL_IMM
        : X86_VEX_EXTRA_FORM_PERMIL_VAR;
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL || descriptor->form != expected_form) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    if (!immediate_form
        && !add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && (!immediate_form
            || add_immediate_value(decoder, 8u, immediate, 0));
#endif
}

static int decode_vcmp_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const int scalar = prefix == X86_SIMD_PREFIX_PF2
        || prefix == X86_SIMD_PREFIX_PF3;
    const int is_double = prefix == X86_SIMD_PREFIX_P66
        || prefix == X86_SIMD_PREFIX_PF2;
    const unsigned int vector_bits = scalar ? 128u
        : ((vex & UINT8_C(0x04)) != 0u ? 256u : 128u);
    const unsigned int scalar_bits = is_double ? 64u : 32u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(1) || opcode != UINT8_C(0xc2)) {
        return -1;
    }

    /* VCMPPS/PD/SS/SD jointly own this complete VEX map-1 row.  Consume
     * ModRM/addressing and imm8 before encountered-prefix policy so a
     * malformed owned encoding cannot hide a truncated payload.  W and
     * scalar L are ignored, and every imm8 value is architecturally read. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* After C4/C5 has been distinguished from LES/LDS, pinned XED
         * aliases C4 B' and the high NDS vvvv bit into the architectural
         * eight-register namespace outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (scalar) {
        form_id = (cdisasm_x86_form_id)(
            (is_double ? UINT16_C(3617) : UINT16_C(3623))
            + (modrm.is_register ? 1u : 0u));
    } else {
        form_id = (cdisasm_x86_form_id)(
            (is_double ? UINT16_C(3595) : UINT16_C(3611))
            + (vector_bits == 256u ? 2u : 0u)
            + (modrm.is_register ? 1u : 0u));
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)vector_bits;
    (void)scalar_bits;
    (void)source_index;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_COMPARE_FP_IMM8) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)
        || !add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (scalar && modrm.is_register) {
        if (!add_named_register_operand_access(
                decoder, xmm_id(modrm.rm), scalar_bits,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
    } else if (!add_vector_rm_operand_access(
            decoder, &modrm, vector_bits,
            scalar ? scalar_bits : vector_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vround_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const int scalar = opcode == UINT8_C(0x0a)
        || opcode == UINT8_C(0x0b);
    const int is_double = opcode == UINT8_C(0x09)
        || opcode == UINT8_C(0x0b);
    const unsigned int vector_bits = scalar ? 128u
        : ((vex & UINT8_C(0x04)) != 0u ? 256u : 128u);
    const unsigned int scalar_bits = is_double ? 64u : 32u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
    const unsigned int expected_form = scalar
        ? X86_VEX_EXTRA_FORM_ROUND_SCALAR
        : X86_VEX_EXTRA_FORM_ROUND_PACKED;
#endif

    if (two_byte || map_select != UINT8_C(3)
        || opcode < UINT8_C(0x08) || opcode > UINT8_C(0x0b)) {
        return -1;
    }

    /* These complete map-3 opcode rows own ModRM/addressing and the trailing
     * imm8 before pp/vvvv or legacy-prefix policy is applied.  W and scalar
     * L are ignored, so every such alias shares the same payload boundary. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Raw R'/X'=1 distinguish C4 from LES.  B' and the scalar NDS high
         * vvvv bit alias into the eight-register namespace outside long
         * mode, matching pinned XED. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        if (scalar) {
            source_index &= 7u;
        }
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(
            decoder, &modrm, scalar ? source_index : 0u)
        || prefix != X86_SIMD_PREFIX_P66
        || (!scalar && (vex & UINT8_C(0x78)) != UINT8_C(0x78))
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (scalar) {
        form_id = (cdisasm_x86_form_id)(
            (is_double ? UINT16_C(8547) : UINT16_C(8549))
            + (modrm.is_register ? 1u : 0u));
    } else {
        form_id = (cdisasm_x86_form_id)(
            (is_double ? UINT16_C(8539) : UINT16_C(8543))
            + (vector_bits == 256u ? 2u : 0u)
            + (modrm.is_register ? 1u : 0u));
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)vector_bits;
    (void)scalar_bits;
    (void)source_index;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL || descriptor->form != expected_form) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    if (scalar
        && !add_vector_register_operand_access(
            decoder, source_index, 128u,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (scalar && modrm.is_register) {
        if (!add_named_register_operand_access(
                decoder, xmm_id(modrm.rm), scalar_bits,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
    } else if (!add_vector_rm_operand_access(
            decoder, &modrm, vector_bits,
            scalar ? scalar_bits : vector_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vpshuf_integer_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    cdisasm_x86_form_id base_form;
    uint64_t immediate;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(1) || opcode != UINT8_C(0x70)) {
        return -1;
    }

    /* The complete VEX.0F.70 row owns ModRM/addressing and its trailing
     * imm8.  Consume both before pp, vvvv, or encountered-prefix policy so
     * incomplete owned encodings always report TRUNCATED first. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED ignores C4 B' for this unary register/memory source
         * after C4 has been distinguished from LES. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix == X86_SIMD_PREFIX_NONE
        || source_index != 0u
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    switch (prefix) {
        case X86_SIMD_PREFIX_P66: base_form = UINT16_C(7891); break;
        case X86_SIMD_PREFIX_PF3: base_form = UINT16_C(7901); break;
        case X86_SIMD_PREFIX_PF2: base_form = UINT16_C(7911); break;
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    if (vector_bits == 256u) {
        base_form = (cdisasm_x86_form_id)(base_form + UINT16_C(4));
    }

#if !USE_EXTRA_OPCODES
    (void)base_form;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_SHUF_INTEGER) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = (cdisasm_x86_form_id)(base_form
        + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, vector_bits == 256u
        ? X86_CAP_AVX | X86_CAP_AVX2 : X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vshuf_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const int is_double = prefix == X86_SIMD_PREFIX_P66;
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(1) || opcode != UINT8_C(0xc6)) {
        return -1;
    }

    /* The complete VEX.0F.C6 row owns ModRM/addressing and its trailing
     * imm8.  Consume both before pp or encountered-prefix policy so an
     * incomplete owned encoding always reports TRUNCATED first. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* C4/C5 disambiguation already constrains R' (and C4 X').  Pinned
         * XED ignores C4 B' and aliases the high NDS vvvv bit into the
         * architectural eight-register namespace outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || (prefix != X86_SIMD_PREFIX_NONE
            && prefix != X86_SIMD_PREFIX_P66)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = (cdisasm_x86_form_id)(
        (is_double ? UINT16_C(8664) : UINT16_C(8674))
        + (vector_bits == 256u ? 6u : 0u)
        + (modrm.is_register ? 1u : 0u));

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)vector_bits;
    (void)immediate;
    (void)is_double;
    (void)source_index;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_SHUF_PACKED) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vtest_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const int is_double = opcode == UINT8_C(0x0f);
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    const unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(2)
        || (opcode != UINT8_C(0x0e) && opcode != UINT8_C(0x0f))) {
        return -1;
    }

    /* The complete VEX.0F38.0E/0F rows own ModRM/addressing.  Consume the
     * payload before reserved-control or encountered-prefix policy so an
     * incomplete owned encoding always reports TRUNCATED first. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED ignores C4 B' outside long mode for this NOVSR family. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66 || w != 0u
        || source_index != 0u
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = (cdisasm_x86_form_id)(
        (is_double ? UINT16_C(8795) : UINT16_C(8799))
        + (vector_bits == 256u ? 2u : 0u)
        + (modrm.is_register ? 1u : 0u));

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)vector_bits;
    (void)is_double;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_TEST_PACKED) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder->prefix_flags |=
        CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vptest_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    const unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(2) || opcode != UINT8_C(0x17)) {
        return -1;
    }

    /* The complete VEX.0F38.17 row belongs to VPTEST.  Consume ModRM and
     * addressing before rejecting pp, vvvv, or encountered legacy prefixes
     * so incomplete owned encodings retain payload-first TRUNCATED status. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED ignores C4 B' outside long mode for this NOVSR family. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66 || source_index != 0u
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = (cdisasm_x86_form_id)(UINT16_C(8319)
        + (vector_bits == 256u ? 2u : 0u)
        + (modrm.is_register ? 1u : 0u));

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)vector_bits;
    (void)w;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_PTEST) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder->prefix_flags |=
        CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vcomi_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = !two_byte
        && (vex & UINT8_C(0x80)) != 0u;
    const int is_double = prefix == X86_SIMD_PREFIX_P66;
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int scalar_bits = is_double ? 64u : 32u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x2e) && opcode != UINT8_C(0x2f))) {
        return -1;
    }

    /* The complete VEX.0F.2E/2F rows own ModRM/addressing.  Consume that
     * payload before rejecting reserved pp/vvvv or encountered legacy
     * prefixes so incomplete owned encodings report TRUNCATED first. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Once C4/C5 is distinguished from LES/LDS, pinned XED ignores the
         * C4 B' bit for this fixed-NOVSR scalar family outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || (prefix != X86_SIMD_PREFIX_NONE
            && prefix != X86_SIMD_PREFIX_P66)
        || source_index != 0u
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x2e)) {
        form_id = (cdisasm_x86_form_id)(
            (is_double ? UINT16_C(8803) : UINT16_C(8809))
            + (modrm.is_register ? 1u : 0u));
    } else {
        form_id = (cdisasm_x86_form_id)(
            (is_double ? UINT16_C(3629) : UINT16_C(3633))
            + (modrm.is_register ? 1u : 0u));
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)scalar_bits;
    (void)w;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_UCOMI_SCALAR) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder->prefix_flags |=
        CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, 128u,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (modrm.is_register) {
        return add_named_register_operand_access(
            decoder, xmm_id(modrm.rm), scalar_bits,
            CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_rm_operand_access(
        decoder, &modrm, 128u, scalar_bits,
        CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vunpck_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const int high = opcode == UINT8_C(0x15);
    const int is_double = prefix == X86_SIMD_PREFIX_P66;
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x14) && opcode != UINT8_C(0x15))) {
        return -1;
    }

    /* Both complete VEX.0F.14/15 rows own ModRM/addressing.  Consume the
     * payload before rejecting pp or encountered legacy prefixes so an
     * incomplete owned encoding reports TRUNCATED first. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* C4/C5 disambiguation constrains R' (and C4 X').  Pinned XED ignores
         * C4 B' and aliases the high NDS vvvv bit into the architectural
         * eight-register namespace outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || (prefix != X86_SIMD_PREFIX_NONE
            && prefix != X86_SIMD_PREFIX_P66)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (high) {
        form_id = (cdisasm_x86_form_id)(
            (is_double
                ? (vector_bits == 256u ? UINT16_C(8831) : UINT16_C(8825))
                : (vector_bits == 256u ? UINT16_C(8841) : UINT16_C(8835)))
            + (modrm.is_register ? 1u : 0u));
    } else {
        form_id = (cdisasm_x86_form_id)(
            (is_double
                ? (vector_bits == 256u ? UINT16_C(8851) : UINT16_C(8845))
                : (vector_bits == 256u ? UINT16_C(8861) : UINT16_C(8855)))
            + (modrm.is_register ? 1u : 0u));
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)vector_bits;
    (void)source_index;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_UNPACK_PACKED) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vphminposuw_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (two_byte || map_select != UINT8_C(2)
        || !is_vphminposuw_opcode(opcode)) {
        return -1;
    }

    /* Own the complete C4 map-2 opcode row and consume ModRM/addressing
     * before rejecting pp/L/vvvv or encountered legacy prefixes. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED ignores C4 B' outside long mode for this NOVSR row. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66
        || (vex & UINT8_C(0x04)) != 0u
        || source_index != 0u
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_PHMINPOSUW) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = (cdisasm_x86_form_id)(UINT16_C(7040)
        + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
            decoder, &modrm, 128u, 128u,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpmovsx_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    static const cdisasm_x86_name_id names[6] = {
        CDISASM_X86_NAME_VPMOVSXBW,
        CDISASM_X86_NAME_VPMOVSXBD,
        CDISASM_X86_NAME_VPMOVSXBQ,
        CDISASM_X86_NAME_VPMOVSXWD,
        CDISASM_X86_NAME_VPMOVSXWQ,
        CDISASM_X86_NAME_VPMOVSXDQ
    };
    static const uint16_t xmm_forms[6] = {
        UINT16_C(7419), UINT16_C(7399), UINT16_C(7409),
        UINT16_C(7439), UINT16_C(7449), UINT16_C(7429)
    };
    static const uint16_t ymm_forms[6] = {
        UINT16_C(7425), UINT16_C(7405), UINT16_C(7415),
        UINT16_C(7445), UINT16_C(7455), UINT16_C(7435)
    };
    static const uint8_t xmm_source_bits[6] = {
        64u, 32u, 16u, 64u, 32u, 64u
    };
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int unused_source =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    unsigned int family;
    unsigned int source_bits;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (two_byte || map_select != UINT8_C(2)
        || !is_vpmovsx_opcode(opcode)) {
        return -1;
    }
    family = (unsigned int)opcode - UINT8_C(0x20);
    source_bits = (unsigned int)xmm_source_bits[family]
        * (vector_bits == 256u ? 2u : 1u);

    /* Each complete opcode row owns ModRM/addressing for every pp/vvvv/W/L
     * combination.  Consume that payload before rejecting reserved controls
     * so an incomplete effective address always reports TRUNCATED first. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Once C4 wins LES disambiguation, pinned XED ignores inverted B'
         * for this NOVSR family and aliases the source/address down. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, unused_source)
        || prefix != X86_SIMD_PREFIX_P66
        || unused_source != 0u
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)names;
    (void)xmm_forms;
    (void)ymm_forms;
    (void)source_bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_PMOVSX_WIDEN
        || descriptor->name_id != names[family]) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = names[family];
    decoder->form_id = (cdisasm_x86_form_id)(
        (vector_bits == 256u ? ymm_forms[family] : xmm_forms[family])
        + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, vector_bits == 256u
        ? X86_CAP_AVX | X86_CAP_AVX2 : X86_CAP_AVX);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    if (modrm.is_register) {
        return add_named_register_operand_access(
            decoder, xmm_id(modrm.rm), source_bits,
            CDISASM_OPERAND_ACCESS_READ);
    }
    return add_rm_operand(decoder, &modrm, source_bits, 1)
        && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpmovzx_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    static const cdisasm_x86_name_id names[6] = {
        CDISASM_X86_NAME_VPMOVZXBW,
        CDISASM_X86_NAME_VPMOVZXBD,
        CDISASM_X86_NAME_VPMOVZXBQ,
        CDISASM_X86_NAME_VPMOVZXWD,
        CDISASM_X86_NAME_VPMOVZXWQ,
        CDISASM_X86_NAME_VPMOVZXDQ
    };
    static const uint16_t xmm_forms[6] = {
        UINT16_C(7524), UINT16_C(7504), UINT16_C(7514),
        UINT16_C(7544), UINT16_C(7554), UINT16_C(7534)
    };
    static const uint16_t ymm_forms[6] = {
        UINT16_C(7530), UINT16_C(7510), UINT16_C(7520),
        UINT16_C(7550), UINT16_C(7560), UINT16_C(7540)
    };
    static const uint8_t xmm_source_bits[6] = {
        64u, 32u, 16u, 64u, 32u, 64u
    };
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int unused_source =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    unsigned int family;
    unsigned int source_bits;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (two_byte || map_select != UINT8_C(2)
        || !is_vpmovzx_opcode(opcode)) {
        return -1;
    }
    family = (unsigned int)opcode - UINT8_C(0x30);
    source_bits = (unsigned int)xmm_source_bits[family]
        * (vector_bits == 256u ? 2u : 1u);

    /* Own the complete rows and consume ModRM/addressing before rejecting
     * pp/vvvv/W/L controls so truncation retains payload-first precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED aliases inverted B' down after C4 wins LES
         * disambiguation for this NOVSR family. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, unused_source)
        || prefix != X86_SIMD_PREFIX_P66
        || unused_source != 0u
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)names;
    (void)xmm_forms;
    (void)ymm_forms;
    (void)source_bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_PMOVZX_WIDEN
        || descriptor->name_id != names[family]) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = names[family];
    decoder->form_id = (cdisasm_x86_form_id)(
        (vector_bits == 256u ? ymm_forms[family] : xmm_forms[family])
        + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, vector_bits == 256u
        ? X86_CAP_AVX | X86_CAP_AVX2 : X86_CAP_AVX);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    if (modrm.is_register) {
        return add_named_register_operand_access(
            decoder, xmm_id(modrm.rm), source_bits,
            CDISASM_OPERAND_ACCESS_READ);
    }
    return add_rm_operand(decoder, &modrm, source_bits, 1)
        && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpextr_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = !two_byte
        && (vex & UINT8_C(0x80)) != 0u;
    const unsigned int unused_source =
        ((unsigned int)(~vex) >> 3) & 15u;
    const int map1_c5 = map_select == UINT8_C(1);
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    unsigned int register_bits;
    unsigned int memory_bits;
    uint64_t immediate;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
    uint8_t descriptor_w = w;
#endif

    if (!is_vpextr_vex_opcode(map_select, opcode)) {
        return -1;
    }

    /* Every owned opcode row includes ModRM/addressing and imm8.  Consume
     * that complete payload before rejecting reserved pp/L/vvvv/W or the
     * map-1 memory shape, preserving truncation precedence. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Once C4/C5 wins LES/LDS disambiguation, pinned XED aliases the
         * inverted B extension into the low register/address namespace.
         * NOVSR remains strict raw vvvv=1111 in every mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(
            decoder, &modrm, unused_source)
        || prefix != X86_SIMD_PREFIX_P66
        || (vex & UINT8_C(0x04)) != 0u
        || unused_source != 0u
        || (map1_c5 && !modrm.is_register)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (map1_c5) {
        name_id = CDISASM_X86_NAME_VPEXTRW;
        form_id = UINT16_C(6979);
        register_bits = 32u;
        memory_bits = 16u;
    } else if (opcode == UINT8_C(0x14)) {
        name_id = CDISASM_X86_NAME_VPEXTRB;
        form_id = modrm.is_register ? UINT16_C(6966) : UINT16_C(6968);
        register_bits = 32u;
        memory_bits = 8u;
    } else if (opcode == UINT8_C(0x15)) {
        name_id = CDISASM_X86_NAME_VPEXTRW;
        form_id = modrm.is_register ? UINT16_C(6978) : UINT16_C(6983);
        register_bits = 32u;
        memory_bits = 16u;
    } else if (w != 0u && decoder->mode == CDISASM_MODE_64) {
        name_id = CDISASM_X86_NAME_VPEXTRQ;
        form_id = modrm.is_register ? UINT16_C(6974) : UINT16_C(6976);
        register_bits = 64u;
        memory_bits = 64u;
    } else {
        /* XED intentionally ignores Sandy Bridge's non-long W=1 erratum. */
        name_id = CDISASM_X86_NAME_VPEXTRD;
        form_id = modrm.is_register ? UINT16_C(6970) : UINT16_C(6972);
        register_bits = 32u;
        memory_bits = 32u;
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    (void)register_bits;
    (void)memory_bits;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (!map1_c5 && opcode == UINT8_C(0x16)
        && decoder->mode != CDISASM_MODE_64) {
        descriptor_w = 0u;
    }
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, descriptor_w);
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_PEXTR
        || descriptor->name_id != name_id) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (modrm.is_register) {
        const unsigned int destination_index = map1_c5
            ? modrm.reg : modrm.rm;

        if (!add_register_operand_access(
                decoder, destination_index, register_bits,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
    } else if (!add_rm_operand(decoder, &modrm, memory_bits, 1)
        || !set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    return add_vector_register_operand_access(
               decoder, map1_c5 ? modrm.rm : modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vpinsr_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = !two_byte
        && (vex & UINT8_C(0x80)) != 0u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    unsigned int register_bits;
    unsigned int memory_bits;
    uint64_t immediate;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
    uint8_t descriptor_w = w;
#endif

    if (!is_vpinsr_vex_opcode(map_select, opcode)) {
        return -1;
    }

    /* These three complete opcode rows own ModRM/addressing and imm8.  Read
     * the whole payload before selector or encountered-prefix policy so a
     * malformed-but-incomplete owned encoding reports TRUNCATED first. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Once C4/C5 has won LES/LDS disambiguation, pinned XED ignores C4
         * B' and aliases the high NDS vvvv bit into the eight-XMM namespace.
         * C5 disambiguation itself fixes R' and that high vvvv bit. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66
        || (vex & UINT8_C(0x04)) != 0u
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (map_select == UINT8_C(1)) {
        name_id = CDISASM_X86_NAME_VPINSRW;
        form_id = modrm.is_register ? UINT16_C(7072) : UINT16_C(7073);
        register_bits = 32u;
        memory_bits = 16u;
    } else if (opcode == UINT8_C(0x20)) {
        name_id = CDISASM_X86_NAME_VPINSRB;
        form_id = modrm.is_register ? UINT16_C(7060) : UINT16_C(7061);
        register_bits = 32u;
        memory_bits = 8u;
    } else if (w != 0u && decoder->mode == CDISASM_MODE_64) {
        name_id = CDISASM_X86_NAME_VPINSRQ;
        form_id = modrm.is_register ? UINT16_C(7068) : UINT16_C(7069);
        register_bits = 64u;
        memory_bits = 64u;
    } else {
        /* XED deliberately does not model Sandy Bridge's non-long W=1
         * erratum: that spelling is the ordinary VPINSRD form. */
        name_id = CDISASM_X86_NAME_VPINSRD;
        form_id = modrm.is_register ? UINT16_C(7064) : UINT16_C(7065);
        register_bits = 32u;
        memory_bits = 32u;
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    (void)register_bits;
    (void)memory_bits;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (map_select == UINT8_C(3) && opcode == UINT8_C(0x22)
        && decoder->mode != CDISASM_MODE_64) {
        descriptor_w = 0u;
    }
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, descriptor_w);
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_PINSR
        || descriptor->name_id != name_id) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, 128u,
            CDISASM_OPERAND_ACCESS_WRITE)
        || !add_vector_register_operand_access(
            decoder, source_index, 128u,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (modrm.is_register) {
        if (!add_register_operand_access(
                decoder, modrm.rm, register_bits,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
    } else if (!add_rm_operand(decoder, &modrm, memory_bits, 1)
        || !set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_horizontal_integer_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    cdisasm_x86_form_id base_form;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (two_byte || map_select != UINT8_C(2)
        || !is_horizontal_integer_opcode(opcode)) {
        return -1;
    }

    /* Own and consume ModRM/addressing before selector or encountered-prefix
     * policy so incomplete rows retain payload-first truncation status. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    switch (opcode) {
        case 0x02: base_form = UINT16_C(7012); break;
        case 0x03: base_form = UINT16_C(7016); break;
        case 0x01: base_form = UINT16_C(7036); break;
        case 0x06: base_form = UINT16_C(7046); break;
        case 0x07: base_form = UINT16_C(7050); break;
        case 0x05: base_form = UINT16_C(7056); break;
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    if (vector_bits == 256u) {
        base_form = (cdisasm_x86_form_id)(base_form + UINT16_C(2));
    }

#if !USE_EXTRA_OPCODES
    (void)base_form;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_HORIZONTAL_INTEGER) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = (cdisasm_x86_form_id)(base_form
        + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, vector_bits == 256u
        ? X86_CAP_AVX | X86_CAP_AVX2 : X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpsign_integer_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    cdisasm_x86_form_id base_form;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (two_byte || map_select != UINT8_C(2)
        || !is_vpsign_integer_opcode(opcode)) {
        return -1;
    }

    /* These three complete opcode rows own ModRM/addressing.  Consume the
     * payload before rejecting reserved pp or encountered legacy prefixes
     * so incomplete owned encodings report TRUNCATED first. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Once C4 has been distinguished from LES, pinned XED ignores B'
         * and aliases the high NDS vvvv bit into the eight-register
         * namespace outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    switch (opcode) {
        case 0x08: base_form = UINT16_C(7921); break;
        case 0x0a: base_form = UINT16_C(7925); break;
        case 0x09: base_form = UINT16_C(7929); break;
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    if (vector_bits == 256u) {
        base_form = (cdisasm_x86_form_id)(base_form + UINT16_C(2));
    }

#if !USE_EXTRA_OPCODES
    (void)base_form;
    (void)source_index;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_SIGN_INTEGER) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = (cdisasm_x86_form_id)(base_form
        + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, vector_bits == 256u
        ? X86_CAP_AVX | X86_CAP_AVX2 : X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vpunpck_integer_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0u
        ? 256u : 128u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    cdisasm_x86_form_id base_form;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    if (map_select != UINT8_C(1)
        || !is_vpunpck_integer_opcode(opcode)) {
        return -1;
    }

    /* These eight complete opcode rows own ModRM/addressing.  Consume the
     * payload before rejecting reserved pp or encountered legacy prefixes
     * so incomplete owned encodings report TRUNCATED first. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED ignores C4 B' and aliases the high NDS vvvv bit into
         * the architectural eight-register namespace outside long mode. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)
        || prefix != X86_SIMD_PREFIX_P66
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    switch (opcode) {
        case 0x68: base_form = UINT16_C(8323); break;
        case 0x6a: base_form = UINT16_C(8333); break;
        case 0x6d: base_form = UINT16_C(8343); break;
        case 0x69: base_form = UINT16_C(8353); break;
        case 0x60: base_form = UINT16_C(8363); break;
        case 0x62: base_form = UINT16_C(8373); break;
        case 0x6c: base_form = UINT16_C(8383); break;
        case 0x61: base_form = UINT16_C(8393); break;
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    if (vector_bits == 256u) {
        base_form = (cdisasm_x86_form_id)(base_form + UINT16_C(4));
    }

#if !USE_EXTRA_OPCODES
    (void)base_form;
    (void)source_index;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix,
        (uint8_t)((vex & UINT8_C(0x80)) != 0u));
    if (descriptor == NULL
        || descriptor->form != X86_VEX_EXTRA_FORM_UNPACK_INTEGER) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    decoder->form_id = (cdisasm_x86_form_id)(base_form
        + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, vector_bits == 256u
        ? X86_CAP_AVX | X86_CAP_AVX2 : X86_CAP_AVX);
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int gfni_vex_opcode_owned(uint8_t map_select, uint8_t opcode)
{
    return (map_select == UINT8_C(3)
            && (opcode == UINT8_C(0xce) || opcode == UINT8_C(0xcf)))
        || (map_select == UINT8_C(2) && opcode == UINT8_C(0xcf));
}

/* Decode the complete classic-VEX GFNI allocation.  Keeping this separate
 * from the generic packed-integer decoder is deliberate: both vector widths
 * are AVX+GFNI (never AVX2), and CE/CF have exact, opposite W semantics in
 * maps 3 and 2. */
static int decode_gfni_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const int affine = map_select == UINT8_C(3);
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0u ? 256u : 128u;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    x86_modrm modrm;
    uint64_t immediate = 0u;

    if (!gfni_vex_opcode_owned(map_select, opcode)) {
        return -1;
    }

    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Once C4 has been distinguished from LES, pinned XED treats B'
         * and the high vvvv bit as aliases in the eight-register modes. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (affine && !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }

    /* These three opcode rows own their complete ModRM/EA and, for affine,
     * imm8 payload before any reserved selector is diagnosed. */
    if (two_byte
        || prefix != X86_SIMD_PREFIX_P66
        || w != (uint8_t)affine
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u
        || !vex_non64_extensions_are_valid(
            decoder, &modrm, source_index)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)vector_bits;
    (void)immediate;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (affine) {
        const int inverse = opcode == UINT8_C(0xcf);
        const cdisasm_x86_form_id base = inverse
            ? (vector_bits == 128u ? UINT16_C(5507) : UINT16_C(5511))
            : (vector_bits == 128u ? UINT16_C(5517) : UINT16_C(5521));

        decoder->name_id = inverse
            ? CDISASM_X86_NAME_VGF2P8AFFINEINVQB
            : CDISASM_X86_NAME_VGF2P8AFFINEQB;
        decoder->form_id = (cdisasm_x86_form_id)(
            base + (modrm.is_register ? 1u : 0u));
    } else {
        const cdisasm_x86_form_id base = vector_bits == 128u
            ? UINT16_C(5527) : UINT16_C(5531);

        decoder->name_id = CDISASM_X86_NAME_VGF2P8MULB;
        decoder->form_id = (cdisasm_x86_form_id)(
            base + (modrm.is_register ? 1u : 0u));
    }
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_GFNI);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)
        || !add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        || !add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return !affine
        || add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_avx_ne_convert_vex(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    const uint8_t prefix = vex & UINT8_C(0x03);
    const uint8_t w = (vex & UINT8_C(0x80)) != 0u;
    const unsigned int source_index =
        ((unsigned int)(~vex) >> 3) & 15u;
    const unsigned int vector_bits =
        (vex & UINT8_C(0x04)) != 0u ? 256u : 128u;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (two_byte || map_select != UINT8_C(2)
        || (opcode != UINT8_C(0x72)
            && opcode != UINT8_C(0xb0)
            && opcode != UINT8_C(0xb1))) {
        return -1;
    }

    /* These rows own ModRM and the complete effective-address payload. */
    decoder->rex = vex_rex_bits(vex_map, vex, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (w != 0u || source_index != 0u
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u
        || (opcode == UINT8_C(0x72)
            && prefix != X86_SIMD_PREFIX_PF3)
        || (opcode == UINT8_C(0xb0) && prefix > X86_SIMD_PREFIX_PF2)
        || (opcode == UINT8_C(0xb1)
            && prefix != X86_SIMD_PREFIX_P66
            && prefix != X86_SIMD_PREFIX_PF3)
        || (opcode != UINT8_C(0x72) && modrm.is_register)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)vector_bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder->used_avx_ne_convert = 1;

    if (opcode == UINT8_C(0x72)) {
        decoder->name_id = CDISASM_X86_NAME_VCVTNEPS2BF16;
        decoder->form_id = (cdisasm_x86_form_id)(vector_bits == 128u
            ? (modrm.is_register ? UINT16_C(3839) : UINT16_C(3837))
            : (modrm.is_register ? UINT16_C(3840) : UINT16_C(3838)));
        return add_vector_register_operand_access(
                   decoder, modrm.reg, 128u,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_rm_operand_access(
                   decoder, &modrm, vector_bits, vector_bits,
                   CDISASM_OPERAND_ACCESS_READ);
    }

    if (opcode == UINT8_C(0xb1)) {
        decoder->name_id = prefix == X86_SIMD_PREFIX_P66
            ? CDISASM_X86_NAME_VBCSTNESH2PS
            : CDISASM_X86_NAME_VBCSTNEBF162PS;
        decoder->form_id = (cdisasm_x86_form_id)(
            (prefix == X86_SIMD_PREFIX_P66 ? UINT16_C(3513)
                                           : UINT16_C(3511))
            + (vector_bits == 256u ? 1u : 0u));
        if (!add_vector_register_operand_access(
                decoder, modrm.reg, vector_bits,
                CDISASM_OPERAND_ACCESS_WRITE)
            || !add_rm_operand(decoder, &modrm, 16u, 1)
            || !set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
        decoder->operand[decoder->operand_count - 1u].broadcast =
            vector_bits == 128u ? CDISASM_X86_BROADCAST_1_TO_4
                                : CDISASM_X86_BROADCAST_1_TO_8;
        return 1;
    }

    if (prefix == X86_SIMD_PREFIX_NONE) {
        decoder->name_id = CDISASM_X86_NAME_VCVTNEOPH2PS;
        form_id = UINT16_C(3831);
    } else if (prefix == X86_SIMD_PREFIX_P66) {
        decoder->name_id = CDISASM_X86_NAME_VCVTNEEPH2PS;
        form_id = UINT16_C(3827);
    } else if (prefix == X86_SIMD_PREFIX_PF3) {
        decoder->name_id = CDISASM_X86_NAME_VCVTNEEBF162PS;
        form_id = UINT16_C(3825);
    } else {
        decoder->name_id = CDISASM_X86_NAME_VCVTNEOBF162PS;
        form_id = UINT16_C(3829);
    }
    decoder->form_id = (cdisasm_x86_form_id)(
        form_id + (vector_bits == 256u ? 1u : 0u));
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_rm_operand(decoder, &modrm, vector_bits / 4u, 1)
        && set_last_operand_access(
               decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vex_extra(
    x86_decoder *decoder,
    uint8_t vex_map,
    uint8_t vex,
    uint8_t map_select,
    uint8_t opcode,
    int two_byte)
{
    uint8_t prefix = vex & UINT8_C(0x03);
    uint8_t w = (vex & UINT8_C(0x80)) != 0;
    unsigned int source_index = ((unsigned int)(~vex) >> 3) & 15u;
    unsigned int vector_bits = (vex & UINT8_C(0x04)) != 0 ? 256u : 128u;
    unsigned int destination_bits;
    unsigned int source_bits;
    unsigned int memory_bits;
    int has_nds_source;
    int form = vex_extra_form_for_encoding(
        map_select, opcode, prefix, w);
    int modern_form = modern_vex_structural_form(
        map_select, opcode, prefix);
    const int is_owned_map1_vor = map_select == UINT8_C(1)
        && opcode == UINT8_C(0x56);
    const int is_owned_map2_vpabs = map_select == UINT8_C(2)
        && opcode >= UINT8_C(0x1c) && opcode <= UINT8_C(0x1e);
    const int is_owned_classic_packed =
        (map_select == UINT8_C(1)
            && (opcode == UINT8_C(0x63)
                || is_classic_packed_compare_opcode(opcode)
                || is_classic_modular_add_sub_opcode(opcode)
                || opcode == UINT8_C(0x67)
                || opcode == UINT8_C(0x6b)))
        || (map_select == UINT8_C(2)
            && (opcode == UINT8_C(0x29) || opcode == UINT8_C(0x2b)
                || opcode == UINT8_C(0x37)))
        || is_packed_integer_minmax_opcode(map_select, opcode);
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_vex_extra_descriptor *descriptor;
#endif

    {
        const int ne_convert_result = decode_avx_ne_convert_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (ne_convert_result >= 0) {
            return ne_convert_result;
        }
    }

    {
        const int gfni_result = decode_gfni_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (gfni_result >= 0) {
            return gfni_result;
        }
    }

    {
        const int vmaskmov_result = decode_vmaskmov_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vmaskmov_result >= 0) {
            return vmaskmov_result;
        }
    }

    {
        const int vpmaskmov_result = decode_vpmaskmov_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vpmaskmov_result >= 0) {
            return vpmaskmov_result;
        }
    }

    {
        const int mxcsr_result = decode_vmxcsr_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (mxcsr_result >= 0) {
            return mxcsr_result;
        }
    }

    {
        const int vpmovsx_result = decode_vpmovsx_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vpmovsx_result >= 0) {
            return vpmovsx_result;
        }
    }

    {
        const int vpmovzx_result = decode_vpmovzx_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vpmovzx_result >= 0) {
            return vpmovzx_result;
        }
    }

    {
        const int vpextr_result = decode_vpextr_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vpextr_result >= 0) {
            return vpextr_result;
        }
    }

    {
        const int vpinsr_result = decode_vpinsr_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vpinsr_result >= 0) {
            return vpinsr_result;
        }
    }

    {
        const int vpshuf_result = decode_vpshuf_integer_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vpshuf_result >= 0) {
            return vpshuf_result;
        }
    }

    {
        const int phminposuw_result = decode_vphminposuw_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (phminposuw_result >= 0) {
            return phminposuw_result;
        }
    }

    {
        const int horizontal_result = decode_horizontal_integer_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (horizontal_result >= 0) {
            return horizontal_result;
        }
    }

    {
        const int vpsign_result = decode_vpsign_integer_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vpsign_result >= 0) {
            return vpsign_result;
        }
    }

    {
        const int vpunpck_result = decode_vpunpck_integer_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vpunpck_result >= 0) {
            return vpunpck_result;
        }
    }

    {
        const int vunpck_result = decode_vunpck_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vunpck_result >= 0) {
            return vunpck_result;
        }
    }

    {
        const int vcomi_result = decode_vcomi_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vcomi_result >= 0) {
            return vcomi_result;
        }
    }

    {
        const int ptest_result = decode_vptest_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (ptest_result >= 0) {
            return ptest_result;
        }
    }

    {
        const int test_result = decode_vtest_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (test_result >= 0) {
            return test_result;
        }
    }

    {
        const int scalar_broadcast_result = decode_vbroadcast_scalar_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (scalar_broadcast_result >= 0) {
            return scalar_broadcast_result;
        }
    }

    {
        const int broadcast128_result = decode_vbroadcast128_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (broadcast128_result >= 0) {
            return broadcast128_result;
        }
    }

    {
        const int broadcast_result = decode_vpbroadcast_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (broadcast_result >= 0) {
            return broadcast_result;
        }
    }

    {
        const int shuf_result = decode_vshuf_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (shuf_result >= 0) {
            return shuf_result;
        }
    }

    {
        const int compare_result = decode_vcmp_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (compare_result >= 0) {
            return compare_result;
        }
    }

    {
        const int round_result = decode_vround_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (round_result >= 0) {
            return round_result;
        }
    }

    {
        const int permil_result = decode_vpermilpd_vpermilps_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (permil_result >= 0) {
            return permil_result;
        }
    }

    {
        const int immediate_perm_result = decode_vpermpd_vpermq_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (immediate_perm_result >= 0) {
            return immediate_perm_result;
        }
    }

    {
        const int perm_result = decode_vpermd_vpermps_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (perm_result >= 0) {
            return perm_result;
        }
    }

    {
        const int perm2_result = decode_vperm2_128_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (perm2_result >= 0) {
            return perm2_result;
        }
    }

    {
        const int ps_lane_result = decode_vextractps_vinsertps_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (ps_lane_result >= 0) {
            return ps_lane_result;
        }
    }

    {
        const int lane_result = decode_lane_insert_extract_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (lane_result >= 0) {
            return lane_result;
        }
    }

    {
        const int blend_result = decode_vpblend_vdpp_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (blend_result >= 0) {
            return blend_result;
        }
    }

    {
        const int vmpsadbw_result = decode_vmpsadbw_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (vmpsadbw_result >= 0) {
            return vmpsadbw_result;
        }
    }

    {
        const int pmovmskb_result = decode_vpmovmskb_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (pmovmskb_result >= 0) {
            return pmovmskb_result;
        }
    }

    {
        const int move_mask_result = decode_vector_move_mask_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (move_mask_result >= 0) {
            return move_mask_result;
        }
    }

    {
        const int duplicate_result = decode_vector_duplicate_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (duplicate_result >= 0) {
            return duplicate_result;
        }
    }

    {
        const int packed_move_result = decode_unaligned_packed_move_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (packed_move_result >= 0) {
            return packed_move_result;
        }
    }

    {
        const int scalar_move_result =
            decode_vector_move_scalar_vex(
                decoder, vex_map, vex, map_select, opcode, two_byte);

        if (scalar_move_result >= 0) {
            return scalar_move_result;
        }
    }

    {
        const int move_result = decode_vector_move_quadword_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (move_result >= 0) {
            return move_result;
        }
    }

    {
        const int load_result = decode_unaligned_integer_load_vex(
            decoder, vex_map, vex, map_select, opcode, two_byte);

        if (load_result >= 0) {
            return load_result;
        }
    }

    {
        const int non_temporal_result =
            decode_non_temporal_aligned_load_vex(
                decoder, vex_map, vex, map_select, opcode, two_byte);

        if (non_temporal_result >= 0) {
            return non_temporal_result;
        }
    }

    {
        const int non_temporal_result =
            decode_non_temporal_vector_store_vex(
                decoder, vex_map, vex, map_select, opcode, two_byte);

        if (non_temporal_result >= 0) {
            return non_temporal_result;
        }
    }

    if (map_select == UINT8_C(7) && opcode == UINT8_C(0xf6)) {
        uint64_t immediate;
        const int is_read = prefix == X86_SIMD_PREFIX_PF2;

        /* MSR_IMM is VEX.0F38F6 with a fixed raw /0 register ModRM and an
         * imm32 selector.  R and X are ignored, B extends the explicit GPR.
         * Intel ISE Programming Reference #319433-060 specifies W0; pinned
         * XED 2026.08 omits that constraint, but GNU 2.47 and Xen enforce it. */
        decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
        decoder->rex_present = 0;
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (!read_immediate_value(decoder, 32u, &immediate)) {
            return 0;
        }
        if (decoder->mode != CDISASM_MODE_64 || w != 0
            || (prefix != X86_SIMD_PREFIX_PF2
                && prefix != X86_SIMD_PREFIX_PF3)
            || (vex & UINT8_C(0x7c)) != UINT8_C(0x78)
            || decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override
            || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0
            || !modrm.is_register || modrm.reg3 != 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (decoder->cpu_id != CDISASM_CPU_X86) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        (void)is_read;
        (void)immediate;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = is_read
            ? CDISASM_X86_NAME_RDMSR : CDISASM_X86_NAME_WRMSRNS;
        decoder->form_id = is_read ? UINT16_C(2572) : UINT16_C(8894);
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        decoder->used_msr_imm = 1;
        if (is_read) {
            return add_register_operand_access(
                    decoder, modrm.rm, 64u,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_immediate_value(decoder, 32u, immediate, 0);
        }
        return add_immediate_value(decoder, 32u, immediate, 0)
            && add_register_operand_access(
                decoder, modrm.rm, 64u, CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (map_select == UINT8_C(7) && opcode == UINT8_C(0xf8)) {
        uint64_t immediate;

        /* USER_MSR's immediate-selector routes are the only allocated VEX
         * map-7 F8 tuples: F2/F3 select URDMSR/UWRMSR, respectively. */
        decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
        decoder->rex_present = 0;
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (!read_immediate_value(decoder, 32u, &immediate)) {
            return 0;
        }
        if (decoder->mode != CDISASM_MODE_64 || w != 0
            || (prefix != X86_SIMD_PREFIX_PF2
                && prefix != X86_SIMD_PREFIX_PF3)
            || (vex & UINT8_C(0x7c)) != UINT8_C(0x78)
            || decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override
            || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0
            || !modrm.is_register || modrm.reg3 != 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = prefix == X86_SIMD_PREFIX_PF2
            ? CDISASM_X86_NAME_URDMSR : CDISASM_X86_NAME_UWRMSR;
        decoder->form_id = prefix == X86_SIMD_PREFIX_PF2
            ? UINT16_C(3355) : UINT16_C(3359);
        decoder_require_caps(decoder, X86_CAP_AMD64);
        if (decoder->cpu_id != CDISASM_CPU_X86) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->used_user_msr = 1;
        if (prefix == X86_SIMD_PREFIX_PF2) {
            return add_register_operand_access(
                    decoder, modrm.rm, 64u,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_immediate_value(decoder, 32u, immediate, 0);
        }
        return add_immediate_value(decoder, 32u, immediate, 0)
            && add_register_operand_access(
                decoder, modrm.rm, 64u, CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (map_select == UINT8_C(2) && opcode == UINT8_C(0x49)
        && prefix == X86_SIMD_PREFIX_PF2 && w != 0) {
        /* ACE BSRINIT is the fixed VEX.0F38.F2.W1/L0 49 /0 tuple.  X/B
         * are ignored because both ModRM fields are fixed low registers;
         * R is constrained by REG=0. */
        decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
        decoder->rex_present = 0;
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (decoder->mode != CDISASM_MODE_64
            || (vex & UINT8_C(0x7c)) != UINT8_C(0x78)
            || modrm.reg != 0 || modrm.rm3 != 0
            || !modrm.is_register) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_BSRINIT;
        decoder->form_id = UINT16_C(378);
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_ACE_1);
        return add_named_register_operand(
                decoder, CDISASM_X86_REG_BSR0, 1024u,
                CDISASM_OPERAND_FLAG_IMPLICIT)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_WRITE);
#endif
    }

    if (vex_kmask_encoding_owned(map_select, opcode, prefix)) {
        return decode_vex_kmask(
            decoder, vex_map, vex, map_select, opcode, two_byte);
    }
    if (form < 0 && modern_form != 0) {
        return decode_modern_vex(
            decoder, vex_map, vex, map_select, opcode,
            two_byte, modern_form);
    }
    if (form < 0) {
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    /* Scalar AVX encodings are LIG: both encoded L values select XMM
     * operands.  Reserved mandatory-prefix combinations remain invalid. */
    if (form == 0 && !is_owned_map1_vor && !is_owned_map2_vpabs
        && !is_owned_classic_packed) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (form == 0) {
        form = is_owned_map2_vpabs
            ? X86_VEX_EXTRA_FORM_UNARY_VECTOR
            : is_owned_classic_packed
                ? X86_VEX_EXTRA_FORM_PACKED_INTEGER
                : X86_VEX_EXTRA_FORM_PACKED_FP;
    }
    if ((form == X86_VEX_EXTRA_FORM_UNARY_VECTOR
            || form == X86_VEX_EXTRA_FORM_UNARY_WIDEN
            || form == X86_VEX_EXTRA_FORM_UNARY_NARROW
            || form == X86_VEX_EXTRA_FORM_MOVE_LOAD
            || form == X86_VEX_EXTRA_FORM_MOVE_STORE
            || form == X86_VEX_EXTRA_FORM_MOVE_STORE_MEMORY
            || form == X86_VEX_EXTRA_FORM_MOVE_MASK
            || form == X86_VEX_EXTRA_FORM_MOVE_LOAD_MEMORY)
        && source_index != 0 && !is_owned_map2_vpabs) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    /* decode_modrm consumes VEX's inverted R/X/B bits through the existing
     * internal REX-shaped addressing state.  rex_present stays clear because
     * no literal REX prefix exists in the byte stream. */
    decoder->rex = vex_rex_bits(vex_map, vex, two_byte);
    if ((is_owned_map1_vor || is_owned_map2_vpabs
            || is_owned_classic_packed)
        && decoder->mode != CDISASM_MODE_64) {
        /* Pinned XED ignores VEX.B for these classic rows outside long mode
         * after C4/C5 has been distinguished from LES/LDS. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
    }
    if ((is_owned_map1_vor || is_owned_classic_packed)
        && decoder->mode != CDISASM_MODE_64) {
        /* These classic NDS rows also ignore the high vvvv bit; unary
         * VPABS instead requires raw vvvv=1111 in every mode. */
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((is_owned_map1_vor || is_owned_map2_vpabs
            || is_owned_classic_packed)
        && ((is_owned_map1_vor && prefix > X86_SIMD_PREFIX_P66)
            || (is_owned_map2_vpabs
                && prefix != X86_SIMD_PREFIX_P66)
            || (is_owned_classic_packed
                && prefix != X86_SIMD_PREFIX_P66)
            || (is_owned_map2_vpabs && source_index != 0)
            || decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override
            || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)form;
    (void)vector_bits;
    (void)destination_bits;
    (void)source_bits;
    (void)memory_bits;
    (void)has_nds_source;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_vex_extra_descriptor(
        map_select, opcode, prefix, w);
    if (descriptor == NULL || descriptor->form != (uint8_t)form) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }

    decoder->name_id = descriptor->name_id;
    if (is_owned_classic_packed) {
        cdisasm_x86_form_id xmm_base;
        cdisasm_x86_form_id ymm_base;

        switch (descriptor->name_id) {
            case CDISASM_X86_NAME_VPACKSSDW:
                xmm_base = UINT16_C(6124);
                ymm_base = UINT16_C(6130);
                break;
            case CDISASM_X86_NAME_VPACKSSWB:
                xmm_base = UINT16_C(6134);
                ymm_base = UINT16_C(6140);
                break;
            case CDISASM_X86_NAME_VPACKUSDW:
                xmm_base = UINT16_C(6144);
                ymm_base = UINT16_C(6148);
                break;
            case CDISASM_X86_NAME_VPACKUSWB:
                xmm_base = UINT16_C(6154);
                ymm_base = UINT16_C(6158);
                break;
            case CDISASM_X86_NAME_VPCMPEQQ:
                xmm_base = UINT16_C(6454);
                ymm_base = UINT16_C(6456);
                break;
            case CDISASM_X86_NAME_VPCMPEQB:
                xmm_base = UINT16_C(6434);
                ymm_base = UINT16_C(6436);
                break;
            case CDISASM_X86_NAME_VPCMPEQD:
                xmm_base = UINT16_C(6444);
                ymm_base = UINT16_C(6446);
                break;
            case CDISASM_X86_NAME_VPCMPEQW:
                xmm_base = UINT16_C(6464);
                ymm_base = UINT16_C(6466);
                break;
            case CDISASM_X86_NAME_VPCMPGTB:
                xmm_base = UINT16_C(6482);
                ymm_base = UINT16_C(6484);
                break;
            case CDISASM_X86_NAME_VPCMPGTD:
                xmm_base = UINT16_C(6492);
                ymm_base = UINT16_C(6494);
                break;
            case CDISASM_X86_NAME_VPCMPGTQ:
                xmm_base = UINT16_C(6502);
                ymm_base = UINT16_C(6504);
                break;
            case CDISASM_X86_NAME_VPCMPGTW:
                xmm_base = UINT16_C(6512);
                ymm_base = UINT16_C(6514);
                break;
            case CDISASM_X86_NAME_VPADDB:
                xmm_base = UINT16_C(6164);
                ymm_base = UINT16_C(6168);
                break;
            case CDISASM_X86_NAME_VPADDW:
                xmm_base = UINT16_C(6234);
                ymm_base = UINT16_C(6238);
                break;
            case CDISASM_X86_NAME_VPADDD:
                xmm_base = UINT16_C(6174);
                ymm_base = UINT16_C(6178);
                break;
            case CDISASM_X86_NAME_VPADDQ:
                xmm_base = UINT16_C(6184);
                ymm_base = UINT16_C(6188);
                break;
            case CDISASM_X86_NAME_VPSUBB:
                xmm_base = UINT16_C(8179);
                ymm_base = UINT16_C(8183);
                break;
            case CDISASM_X86_NAME_VPSUBW:
                xmm_base = UINT16_C(8249);
                ymm_base = UINT16_C(8253);
                break;
            case CDISASM_X86_NAME_VPSUBD:
                xmm_base = UINT16_C(8189);
                ymm_base = UINT16_C(8193);
                break;
            case CDISASM_X86_NAME_VPSUBQ:
                xmm_base = UINT16_C(8199);
                ymm_base = UINT16_C(8203);
                break;
            case CDISASM_X86_NAME_VPMAXSB:
                xmm_base = UINT16_C(7160);
                ymm_base = UINT16_C(7166);
                break;
            case CDISASM_X86_NAME_VPMAXSD:
                xmm_base = UINT16_C(7170);
                ymm_base = UINT16_C(7176);
                break;
            case CDISASM_X86_NAME_VPMAXSW:
                xmm_base = UINT16_C(7186);
                ymm_base = UINT16_C(7192);
                break;
            case CDISASM_X86_NAME_VPMAXUB:
                xmm_base = UINT16_C(7196);
                ymm_base = UINT16_C(7200);
                break;
            case CDISASM_X86_NAME_VPMAXUD:
                xmm_base = UINT16_C(7206);
                ymm_base = UINT16_C(7210);
                break;
            case CDISASM_X86_NAME_VPMAXUW:
                xmm_base = UINT16_C(7222);
                ymm_base = UINT16_C(7226);
                break;
            case CDISASM_X86_NAME_VPMINSB:
                xmm_base = UINT16_C(7232);
                ymm_base = UINT16_C(7238);
                break;
            case CDISASM_X86_NAME_VPMINSD:
                xmm_base = UINT16_C(7242);
                ymm_base = UINT16_C(7248);
                break;
            case CDISASM_X86_NAME_VPMINSW:
                xmm_base = UINT16_C(7258);
                ymm_base = UINT16_C(7264);
                break;
            case CDISASM_X86_NAME_VPMINUB:
                xmm_base = UINT16_C(7268);
                ymm_base = UINT16_C(7272);
                break;
            case CDISASM_X86_NAME_VPMINUD:
                xmm_base = UINT16_C(7278);
                ymm_base = UINT16_C(7282);
                break;
            case CDISASM_X86_NAME_VPMINUW:
                xmm_base = UINT16_C(7294);
                ymm_base = UINT16_C(7298);
                break;
            default:
                return decoder_fail(
                    decoder, CDISASM_STATUS_INTERNAL_ERROR);
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            (vector_bits == 256u ? ymm_base : xmm_base)
            + (modrm.is_register ? 1u : 0u));
    } else if (is_owned_map2_vpabs) {
        cdisasm_x86_form_id base;

        switch (descriptor->name_id) {
            case CDISASM_X86_NAME_VPABSB:
                base = vector_bits == 256u
                    ? UINT16_C(6094) : UINT16_C(6088);
                break;
            case CDISASM_X86_NAME_VPABSD:
                base = vector_bits == 256u
                    ? UINT16_C(6104) : UINT16_C(6098);
                break;
            case CDISASM_X86_NAME_VPABSW:
                base = vector_bits == 256u
                    ? UINT16_C(6120) : UINT16_C(6114);
                break;
            default:
                return decoder_fail(
                    decoder, CDISASM_STATUS_INTERNAL_ERROR);
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            base + (modrm.is_register ? 1u : 0u));
    } else if (opcode == UINT8_C(0x56) && map_select == UINT8_C(1)) {
        switch (descriptor->name_id) {
            case CDISASM_X86_NAME_VORPD:
                decoder->form_id = (cdisasm_x86_form_id)(
                    (vector_bits == 256u
                        ? UINT16_C(6058) : UINT16_C(6054))
                    + (modrm.is_register ? 1u : 0u));
                break;
            case CDISASM_X86_NAME_VORPS:
                decoder->form_id = (cdisasm_x86_form_id)(
                    (vector_bits == 256u
                        ? UINT16_C(6068) : UINT16_C(6064))
                    + (modrm.is_register ? 1u : 0u));
                break;
            default:
                break;
        }
    } else if (opcode == UINT8_C(0x59)
        && map_select == UINT8_C(1)) {
        switch (descriptor->name_id) {
            case CDISASM_X86_NAME_VMULPD:
                decoder->form_id = (cdisasm_x86_form_id)(
                    (vector_bits == 256u
                        ? UINT16_C(6018) : UINT16_C(6012))
                    + (modrm.is_register ? 1u : 0u));
                break;
            case CDISASM_X86_NAME_VMULPS:
                decoder->form_id = (cdisasm_x86_form_id)(
                    (vector_bits == 256u
                        ? UINT16_C(6034) : UINT16_C(6028))
                    + (modrm.is_register ? 1u : 0u));
                break;
            case CDISASM_X86_NAME_VMULSD:
                decoder->form_id = (cdisasm_x86_form_id)(
                    UINT16_C(6038) + (modrm.is_register ? 1u : 0u));
                break;
            case CDISASM_X86_NAME_VMULSS:
                decoder->form_id = (cdisasm_x86_form_id)(
                    UINT16_C(6044) + (modrm.is_register ? 1u : 0u));
                break;
            default:
                break;
        }
    }
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (form == X86_VEX_EXTRA_FORM_VARIABLE_SHIFT
        || (is_owned_map2_vpabs && vector_bits == 256u)
        || (form == X86_VEX_EXTRA_FORM_PACKED_INTEGER
            && vector_bits == 256)) {
        decoder_require_caps(decoder, X86_CAP_AVX2);
    }

    if (form == X86_VEX_EXTRA_FORM_MOVE_LOAD
        || form == X86_VEX_EXTRA_FORM_MOVE_STORE
        || form == X86_VEX_EXTRA_FORM_MOVE_STORE_MEMORY
        || form == X86_VEX_EXTRA_FORM_MOVE_MASK
        || form == X86_VEX_EXTRA_FORM_MOVE_LOAD_MEMORY) {
        if (form == X86_VEX_EXTRA_FORM_MOVE_MASK) {
            if (!modrm.is_register) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_register_operand_access(
                       decoder, modrm.reg, 32u,
                       CDISASM_OPERAND_ACCESS_WRITE)
                && add_vector_register_operand_access(
                       decoder, modrm.rm, vector_bits,
                       CDISASM_OPERAND_ACCESS_READ);
        }
        if ((form == X86_VEX_EXTRA_FORM_MOVE_STORE_MEMORY
                || form == X86_VEX_EXTRA_FORM_MOVE_LOAD_MEMORY)
            && modrm.is_register) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (form == X86_VEX_EXTRA_FORM_MOVE_LOAD
            || form == X86_VEX_EXTRA_FORM_MOVE_LOAD_MEMORY) {
            return add_vector_register_operand_access(
                       decoder, modrm.reg, vector_bits,
                       CDISASM_OPERAND_ACCESS_WRITE)
                && add_vector_rm_operand_access(
                       decoder, &modrm, vector_bits, vector_bits,
                       CDISASM_OPERAND_ACCESS_READ);
        }
        return add_vector_rm_operand_access(
                   decoder, &modrm, vector_bits, vector_bits,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                   decoder, modrm.reg, vector_bits,
                   CDISASM_OPERAND_ACCESS_READ);
    }

    destination_bits = vector_bits;
    source_bits = vector_bits;
    memory_bits = vector_bits;
    has_nds_source = form == X86_VEX_EXTRA_FORM_PACKED_FP
        || form == X86_VEX_EXTRA_FORM_SCALAR_FP
        || form == X86_VEX_EXTRA_FORM_PACKED_INTEGER
        || form == X86_VEX_EXTRA_FORM_VARIABLE_SHIFT;
    if (form == X86_VEX_EXTRA_FORM_SCALAR_FP) {
        destination_bits = 128u;
        source_bits = 128u;
        memory_bits = prefix == X86_SIMD_PREFIX_PF3 ? 32u : 64u;
    } else if (form == X86_VEX_EXTRA_FORM_UNARY_WIDEN) {
        source_bits = 128u;
        memory_bits = vector_bits / 2u;
    } else if (form == X86_VEX_EXTRA_FORM_UNARY_NARROW) {
        destination_bits = 128u;
    }

    if (!add_vector_register_operand_access(
            decoder,
            modrm.reg,
            destination_bits,
            CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    if (has_nds_source
        && !add_vector_register_operand_access(
            decoder,
            source_index,
            source_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return add_vector_rm_operand_access(
        decoder,
        &modrm,
        source_bits,
        memory_bits,
        CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vex2(x86_decoder *decoder)
{
    x86_modrm legacy_modrm;
    uint8_t vex;
    uint8_t opcode;
    uint8_t legacy_prefix_size = decoder->encoding.prefix_size;

    if (!read_u8(decoder, &vex)) {
        return 0;
    }
    if (decoder->mode != CDISASM_MODE_64
        && (vex & UINT8_C(0xc0)) != UINT8_C(0xc0)) {
        /* C5 /r is the legacy LDS opcode outside long mode. */
        --decoder->position;
        if (!decode_modrm(decoder, &legacy_modrm)) {
            return 0;
        }
        if (legacy_modrm.is_register) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = CDISASM_X86_NAME_LDS;
        return add_register_operand_access(
                   decoder, legacy_modrm.reg, decoder->operand_bits,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_rm_operand(
                   decoder, &legacy_modrm,
                   decoder->operand_bits == 16u ? 32u : 48u, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    /* Consume the complete fixed VEX/opcode portion before policy checks. */
    if (!read_u8(decoder, &opcode)) {
        return 0;
    }
    if (decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0) {
        if (opcode == UINT8_C(0x14)
            || opcode == UINT8_C(0x15)
            || is_vpunpck_integer_opcode(opcode)
            || opcode == UINT8_C(0x2e)
            || opcode == UINT8_C(0x2f)
            || opcode == UINT8_C(0xc2)
            || opcode == UINT8_C(0x56)
            || opcode == UINT8_C(0xc6)
            || opcode == UINT8_C(0x63)
            || is_classic_packed_compare_opcode(opcode)
            || is_classic_modular_add_sub_opcode(opcode)
            || is_packed_integer_minmax_opcode(UINT8_C(1), opcode)
            || opcode == UINT8_C(0x67)
            || opcode == UINT8_C(0x6b)
            || opcode == UINT8_C(0x70)
            || opcode == UINT8_C(0xd7)
            || opcode == UINT8_C(0xc4)
            || opcode == UINT8_C(0xc5)
            || opcode == UINT8_C(0xae)) {
            /* Floating/integer VUNPCK, VCMP, VCOMI/VUCOMI, and VOR own the
             * complete payload even when a legacy prefix is reserved, as do
             * the map-1 VPACK rows; defer until decode_vex_extra. */
        } else {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    decoder->prefix_flags |= CDISASM_PREFIX_VEX;
    decoder->encoding.prefix_size = (uint8_t)(legacy_prefix_size + 2u);
    decoder->encoding.opcode_offset = (uint8_t)(legacy_prefix_size + 2u);
    decoder->encoding.opcode_size = 1;
    if (opcode == UINT8_C(0x77)) {
        if ((vex & UINT8_C(0x7b)) != UINT8_C(0x78)) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = (vex & UINT8_C(0x04)) != 0
            ? CDISASM_X86_NAME_VZEROALL
            : CDISASM_X86_NAME_VZEROUPPER;
        return 1;
    }
    return decode_vex_extra(decoder, 0, vex, UINT8_C(1), opcode, 1);
}

static int decode_vex3(x86_decoder *decoder)
{
    x86_modrm legacy_modrm;
    uint8_t vex_map;
    uint8_t map_select;
    uint8_t vex;
    uint8_t opcode;
    uint8_t legacy_prefix_size = decoder->encoding.prefix_size;

    if (!read_u8(decoder, &vex_map)) {
        return 0;
    }
    if (decoder->mode != CDISASM_MODE_64
        && (vex_map & UINT8_C(0xc0)) != UINT8_C(0xc0)) {
        /* C4 /r is the legacy LES opcode outside long mode. */
        --decoder->position;
        if (!decode_modrm(decoder, &legacy_modrm)) {
            return 0;
        }
        if (legacy_modrm.is_register) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = CDISASM_X86_NAME_LES;
        return add_register_operand_access(
                   decoder, legacy_modrm.reg, decoder->operand_bits,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_rm_operand(
                   decoder, &legacy_modrm,
                   decoder->operand_bits == 16u ? 32u : 48u, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    /* Consume all VEX fields and the opcode before policy checks. */
    if (!read_u8(decoder, &vex) || !read_u8(decoder, &opcode)) {
        return 0;
    }
    map_select = vex_map & UINT8_C(0x1f);
    if ((decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override
            || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0)
        && !(map_select == UINT8_C(7)
            && (opcode == UINT8_C(0xf6)
                || opcode == UINT8_C(0xf8)))
        && !(map_select == UINT8_C(1)
            && (opcode == UINT8_C(0x14)
                || opcode == UINT8_C(0x15)
                || is_vpunpck_integer_opcode(opcode)
                || opcode == UINT8_C(0x2e)
                || opcode == UINT8_C(0x2f)
                || opcode == UINT8_C(0xc2)
                || opcode == UINT8_C(0x56)
                || opcode == UINT8_C(0xc6)
                || is_packed_integer_minmax_opcode(
                    UINT8_C(1), opcode)
                || opcode == UINT8_C(0x70)
                || opcode == UINT8_C(0xd7)
                || opcode == UINT8_C(0xc4)
                || opcode == UINT8_C(0xc5)
                || opcode == UINT8_C(0xae)))
        && !(map_select == UINT8_C(2)
            && opcode >= UINT8_C(0x1c)
            && opcode <= UINT8_C(0x1e))
        && !(map_select == UINT8_C(2)
            && (opcode == UINT8_C(0x8c)
                || opcode == UINT8_C(0x8e)))
        && !(map_select == UINT8_C(2)
            && (opcode == UINT8_C(0x72)
                || opcode == UINT8_C(0xb0)
                || opcode == UINT8_C(0xb1)))
        && !(map_select == UINT8_C(1)
            && (opcode == UINT8_C(0x63)
                || is_classic_packed_compare_opcode(opcode)
                || is_classic_modular_add_sub_opcode(opcode)
                || opcode == UINT8_C(0x67)
                || opcode == UINT8_C(0x6b)))
        && !(map_select == UINT8_C(2)
            && (opcode == UINT8_C(0x29)
                || opcode == UINT8_C(0x2b)
                || opcode == UINT8_C(0x37)))
        && !is_packed_integer_minmax_opcode(map_select, opcode)
        && !gfni_vex_opcode_owned(map_select, opcode)) {
        if (map_select == UINT8_C(2)
            && (is_vphminposuw_opcode(opcode)
                || is_horizontal_integer_opcode(opcode)
                || is_vpsign_integer_opcode(opcode)
                || opcode == UINT8_C(0x0e) || opcode == UINT8_C(0x0f)
                || opcode == UINT8_C(0x17)
                || opcode == UINT8_C(0x18) || opcode == UINT8_C(0x19)
                || opcode == UINT8_C(0x1a) || opcode == UINT8_C(0x5a)
                || is_vpmovsx_opcode(opcode)
                || is_vpmovzx_opcode(opcode)
                || opcode == UINT8_C(0x58) || opcode == UINT8_C(0x59)
                || opcode == UINT8_C(0x78) || opcode == UINT8_C(0x79)
                || (opcode >= UINT8_C(0x2c)
                    && opcode <= UINT8_C(0x2f))
                || opcode == UINT8_C(0x0c) || opcode == UINT8_C(0x0d)
                || opcode == UINT8_C(0x16) || opcode == UINT8_C(0x36))) {
            /* VEX broadcasts and the fixed-width map-2 permutations own
             * ModRM/addressing even with a reserved encountered legacy
             * prefix; reject after consuming it. */
        } else if (map_select == UINT8_C(3)
            && (opcode == UINT8_C(0x00)
                || opcode == UINT8_C(0x01)
                || opcode == UINT8_C(0x02)
                || opcode == UINT8_C(0x04)
                || opcode == UINT8_C(0x05)
                || opcode == UINT8_C(0x06)
                || opcode == UINT8_C(0x08)
                || opcode == UINT8_C(0x09)
                || opcode == UINT8_C(0x0a)
                || opcode == UINT8_C(0x0b)
                || opcode == UINT8_C(0x0c)
                || opcode == UINT8_C(0x0d)
                || opcode == UINT8_C(0x0e)
                || opcode == UINT8_C(0x14)
                || opcode == UINT8_C(0x15)
                || opcode == UINT8_C(0x16)
                || opcode == UINT8_C(0x17)
                || opcode == UINT8_C(0x18)
                || opcode == UINT8_C(0x19)
                || opcode == UINT8_C(0x21)
                || opcode == UINT8_C(0x38)
                || opcode == UINT8_C(0x39)
                || opcode == UINT8_C(0x46)
                || opcode == UINT8_C(0x4a)
                || opcode == UINT8_C(0x4b)
                || opcode == UINT8_C(0x4c)
                || opcode == UINT8_C(0x40)
                || opcode == UINT8_C(0x41)
                || opcode == UINT8_C(0x20)
                || opcode == UINT8_C(0x22))) {
            /* The immediate permutation, rounding, lane insert/extract,
             * blend, and dot-product families own ModRM/addressing plus
             * their trailing byte even when a legacy prefix is reserved;
             * defer rejection until after that complete payload is
             * consumed. */
        } else {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    if (map_select == 0 || map_select == 4
        || map_select == 6 || map_select > 7
        || (map_select == 7
            && opcode != UINT8_C(0xf6)
            && opcode != UINT8_C(0xf8))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    /* Outside long mode all three inverted extension bits must encode zero.
     * The C4/LES disambiguation above already constrains R' and X', but an
     * explicit raw-field check is required for B': some ModRM address forms
     * hide its semantic effect and must not make the reserved encoding pass.
     * Register-only AVX-512 K forms are an architectural exception: their
     * B/X fields are ignored and their custom decoder validates R/GPR use.
     * VEX map-1 opcode 50 is the other narrow exception: VMOVMSK's B field
     * is ignored outside long mode and its dedicated decoder clears it.
     * The fixed VMOVD/VMOVQ selectors, scalar VMOVSD/VMOVSS, VCMP and
     * VCOMI/VUCOMI, packed floating/integer VUNPCK, unary VPABSB/W/D, packed
     * VTEST, and classic packed ternary rows likewise ignore B outside long
     * mode. */
    if (decoder->mode != CDISASM_MODE_64
        && (vex_map & UINT8_C(0xe0)) != UINT8_C(0xe0)
        && !(map_select == UINT8_C(1)
            && (opcode == UINT8_C(0x50)
                || opcode == UINT8_C(0x70)
                || opcode == UINT8_C(0xd7)
                || opcode == UINT8_C(0xae)))
        && !(map_select == UINT8_C(1)
            && (opcode == UINT8_C(0x14) || opcode == UINT8_C(0x15)))
        && !(map_select == UINT8_C(1)
            && is_vpunpck_integer_opcode(opcode))
        && !(map_select == UINT8_C(1)
            && (opcode == UINT8_C(0x2e) || opcode == UINT8_C(0x2f)))
        && !(map_select == UINT8_C(1) && opcode == UINT8_C(0xc2))
        && !(map_select == UINT8_C(1) && opcode == UINT8_C(0x56))
        && !(map_select == UINT8_C(1) && opcode == UINT8_C(0xc6))
        && !(map_select == UINT8_C(2)
            && opcode >= UINT8_C(0x1c) && opcode <= UINT8_C(0x1e))
        && !(map_select == UINT8_C(2)
            && (is_vphminposuw_opcode(opcode)
                || is_vpmovsx_opcode(opcode)
                || is_vpmovzx_opcode(opcode)
                || is_horizontal_integer_opcode(opcode)
                || is_vpsign_integer_opcode(opcode)
                || opcode == UINT8_C(0x0e)
                || opcode == UINT8_C(0x0f)
                || opcode == UINT8_C(0x17)))
        && !(map_select == UINT8_C(2)
            && (opcode == UINT8_C(0x72)
                || opcode == UINT8_C(0xb0)
                || opcode == UINT8_C(0xb1)))
        && !(map_select == UINT8_C(1)
            && (opcode == UINT8_C(0x63)
                || is_classic_packed_compare_opcode(opcode)
                || is_classic_modular_add_sub_opcode(opcode)
                || opcode == UINT8_C(0x67)
                || opcode == UINT8_C(0x6b)))
        && !(map_select == UINT8_C(2)
            && (opcode == UINT8_C(0x29)
                || opcode == UINT8_C(0x2b)
                || opcode == UINT8_C(0x37)))
        && !is_packed_integer_minmax_opcode(map_select, opcode)
        && !gfni_vex_opcode_owned(map_select, opcode)
        && !vex_vmovdq_non64_b_is_ignored(
            map_select, opcode, vex)
        && !vex_vmov_non64_b_is_ignored(
            map_select, opcode, vex)
        && !vex_map3_classic_non64_b_is_ignored(
            map_select, opcode)
        && !vex_vpbroadcast_non64_b_is_ignored(
            map_select, opcode)
        && !vex_map2_permute_non64_b_is_ignored(
            map_select, opcode)
        && !vex_vmaskmov_non64_b_is_ignored(
            map_select, opcode)
        && !vex_kmask_encoding_owned(
            map_select, opcode, vex & UINT8_C(0x03))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->prefix_flags |= CDISASM_PREFIX_VEX;
    decoder->encoding.prefix_size = (uint8_t)(legacy_prefix_size + 3u);
    decoder->encoding.opcode_offset = (uint8_t)(legacy_prefix_size + 3u);
    decoder->encoding.opcode_size = 1;
    if (map_select == UINT8_C(1) && opcode == UINT8_C(0x77)) {
        if ((vex & UINT8_C(0x7b)) != UINT8_C(0x78)) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = (vex & UINT8_C(0x04)) != 0
            ? CDISASM_X86_NAME_VZEROALL
            : CDISASM_X86_NAME_VZEROUPPER;
        return 1;
    }
    return decode_vex_extra(
        decoder, vex_map, vex, map_select, opcode, 0);
}

static const x86_xop_descriptor *find_xop_descriptor(
    uint8_t map_select,
    uint8_t opcode)
{
    size_t index;

    for (index = 0; index < sizeof(x86_xop_map) / sizeof(x86_xop_map[0]);
         ++index) {
        if (x86_xop_map[index].map == map_select
            && x86_xop_map[index].opcode == opcode) {
            return &x86_xop_map[index];
        }
    }
    return NULL;
}

static int decode_xop(x86_decoder *decoder)
{
    uint8_t xop_map;
    uint8_t xop;
    uint8_t opcode;
    uint8_t map_select;
    uint8_t prefix;
    uint8_t w;
    uint8_t legacy_prefix_size = decoder->encoding.prefix_size;
    unsigned int source_index;
    unsigned int immediate_reg = 0;
    unsigned int vector_bits;
    uint64_t immediate = 0;
    int form = 0;
    int has_imm8 = 0;
    int is_exact_vpcmov = 0;
    int is_exact_vpperm = 0;
    int is_exact_xop_selector = 0;
    x86_modrm modrm;
    const x86_xop_descriptor *descriptor;

    if (!read_u8(decoder, &xop_map)
        || !read_u8(decoder, &xop)
        || !read_u8(decoder, &opcode)) {
        return 0;
    }
    map_select = xop_map & UINT8_C(0x1f);
    if (map_select < 8 || map_select > 10) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    descriptor = find_xop_descriptor(map_select, opcode);
    is_exact_vpcmov = descriptor != NULL
        && descriptor->form == X86_XOP_FORM_PCMOV;
    is_exact_vpperm = descriptor != NULL
        && descriptor->form == X86_XOP_FORM_PERMUTE
        && descriptor->form_base != CDISASM_X86_FORM_NONE;
    is_exact_xop_selector = is_exact_vpcmov || is_exact_vpperm;
    if (!is_exact_xop_selector
        && (decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    /* In non-64-bit modes XOP.R and XOP.X remain reserved and must be one,
     * while XOP.B is architecturally ignored rather than reserved.  The
     * pinned exact selector rows alias all three extension bits, plus the
     * high vvvv and selector bits, in non-long modes. */
    if (!is_exact_xop_selector && decoder->mode != CDISASM_MODE_64
        && (xop_map & UINT8_C(0xc0)) != UINT8_C(0xc0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    prefix = xop & UINT8_C(0x03);
    w = (xop & UINT8_C(0x80)) != 0;
    source_index = ((unsigned int)(~xop) >> 3) & 15u;
    if (!is_exact_xop_selector && prefix != X86_SIMD_PREFIX_NONE) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (descriptor == NULL) {
        return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    form = descriptor->form;
    switch (form) {
        case X86_XOP_FORM_ROTATE_IMMEDIATE:
            if (w != 0 || source_index != 0
                || (xop & UINT8_C(0x04)) != 0) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            has_imm8 = 1;
            break;

        case X86_XOP_FORM_PCMOV:
            has_imm8 = 1;
            break;

        case X86_XOP_FORM_MAC:
        case X86_XOP_FORM_COMPARE:
            if (w != 0 || (xop & UINT8_C(0x04)) != 0) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            has_imm8 = 1;
            break;

        case X86_XOP_FORM_PERMUTE:
            if (!is_exact_vpperm && (xop & UINT8_C(0x04)) != 0) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            has_imm8 = 1;
            break;

        case X86_XOP_FORM_ROTATE_REGISTER:
        case X86_XOP_FORM_SHIFT_REGISTER:
            if ((xop & UINT8_C(0x04)) != 0) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            break;

        case X86_XOP_FORM_UNARY_PACKED:
            if (w != 0 || source_index != 0) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            break;

        case X86_XOP_FORM_UNARY_SCALAR32:
        case X86_XOP_FORM_UNARY_SCALAR64:
        case X86_XOP_FORM_UNARY_VECTOR128:
            if (w != 0 || source_index != 0
                || (xop & UINT8_C(0x04)) != 0) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            break;

        default:
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    vector_bits = (xop & UINT8_C(0x04)) != 0 ? 256u : 128u;

    decoder->prefix_flags |= CDISASM_PREFIX_XOP;
    decoder->encoding.prefix_size = (uint8_t)(legacy_prefix_size + 3u);
    decoder->encoding.opcode_offset = (uint8_t)(legacy_prefix_size + 3u);
    decoder->encoding.opcode_size = 1;
    decoder->rex = vex_rex_bits(xop_map, xop, 0);
    if (decoder->mode != CDISASM_MODE_64) {
        /* Exact selector rows alias every XOP extension outside long mode.
         * Other XOP rows retain the established B-only alias policy. */
        decoder->rex &= (uint8_t)~(is_exact_xop_selector
            ? UINT8_C(0x07) : UINT8_C(0x01));
        if (is_exact_xop_selector) {
            source_index &= 7u;
        }
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!vex_non64_extensions_are_valid(decoder, &modrm, source_index)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (has_imm8) {
        if (is_exact_xop_selector) {
            uint8_t selector;

            /* SE_IMM8 is an opcode selector, not an immediate operand.  Its
             * high nibble names a source and its low nibble is ignored. */
            decoder->encoding.selector_offset = (uint8_t)decoder->position;
            if (!read_u8(decoder, &selector)) {
                return 0;
            }
            immediate = selector;
        } else if (!read_immediate_value(decoder, 8, &immediate)) {
            return 0;
        }
    }
    if (is_exact_xop_selector
        && (prefix != X86_SIMD_PREFIX_NONE
            || (is_exact_vpperm && (xop & UINT8_C(0x04)) != 0)
            || decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override
            || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    immediate_reg = (unsigned int)(immediate >> 4)
        & (decoder->mode == CDISASM_MODE_64 ? 15u : 7u);

#if !USE_EXTRA_OPCODES
    (void)immediate_reg;
    (void)vector_bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = descriptor->name_id;
    if (is_exact_vpcmov) {
        if (descriptor->form_base == CDISASM_X86_FORM_NONE) {
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
        }
        decoder->form_id = (cdisasm_x86_form_id)(descriptor->form_base
            + (vector_bits == 256u ? 3u : 0u)
            + (modrm.is_register ? 2u : (w != 0 ? 1u : 0u)));
    } else if (is_exact_vpperm) {
        if (descriptor->form_base == CDISASM_X86_FORM_NONE) {
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
        }
        decoder->form_id = (cdisasm_x86_form_id)(descriptor->form_base
            + (modrm.is_register ? 2u : (w != 0 ? 1u : 0u)));
    }
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_XOP);

    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    if (form == X86_XOP_FORM_ROTATE_IMMEDIATE) {
        return add_vector_rm_operand_access(
                decoder, &modrm, vector_bits, vector_bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_immediate_value(decoder, 8, immediate, 0);
    }
    if (form == X86_XOP_FORM_UNARY_PACKED
        || form == X86_XOP_FORM_UNARY_SCALAR32
        || form == X86_XOP_FORM_UNARY_SCALAR64
        || form == X86_XOP_FORM_UNARY_VECTOR128) {
        const unsigned int memory_bits =
            form == X86_XOP_FORM_UNARY_SCALAR32
                ? 32u
                : (form == X86_XOP_FORM_UNARY_SCALAR64
                    ? 64u
                    : (form == X86_XOP_FORM_UNARY_VECTOR128
                        ? 128u : vector_bits));

        return add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, memory_bits,
            CDISASM_OPERAND_ACCESS_READ);
    }
    if (form == X86_XOP_FORM_ROTATE_REGISTER
        || form == X86_XOP_FORM_SHIFT_REGISTER) {
        if (w == 0) {
            return add_vector_rm_operand_access(
                    decoder, &modrm, vector_bits, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_vector_register_operand_access(
                    decoder, source_index, vector_bits,
                    CDISASM_OPERAND_ACCESS_READ);
        }
        return add_vector_register_operand_access(
                decoder, source_index, vector_bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_vector_rm_operand_access(
                decoder, &modrm, vector_bits, vector_bits,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (form == X86_XOP_FORM_COMPARE) {
        return add_vector_register_operand_access(
                decoder, source_index, vector_bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_vector_rm_operand_access(
                decoder, &modrm, vector_bits, vector_bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_immediate_value(decoder, 8, immediate, 0);
    }
    if (!add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (w == 0) {
        return add_vector_rm_operand_access(
                decoder, &modrm, vector_bits, vector_bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_vector_register_operand_access(
                decoder, immediate_reg, vector_bits,
                CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_register_operand_access(
            decoder, immediate_reg, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
            decoder, &modrm, vector_bits, vector_bits,
            CDISASM_OPERAND_ACCESS_READ);
#endif
}

typedef struct x86_evex_shape {
    uint8_t form;
    uint8_t w;
    uint8_t element_bits;
    uint8_t flags;
} x86_evex_shape;

/*
 * Keep structural recognition outside USE_EXTRA_OPCODES.  A build with the
 * optional semantic tables disabled must still distinguish a complete,
 * controlled EVEX encoding from a truncated or reserved one.
 */
static int evex_shape_for_encoding(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w,
    x86_evex_shape *shape)
{
    *shape = (x86_evex_shape){0};

    /* AVX512-BF16 VCVTNEPS2BF16: the selected VL describes the FP32
     * source while the BF16 destination is narrowed by two. */
    if (map_select == 2 && opcode == UINT8_C(0x72)
        && prefix == X86_SIMD_PREFIX_PF3 && w == 0) {
        shape->form = X86_EVEX_FORM_UNARY_NARROW;
        shape->w = 0;
        shape->element_bits = 32;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST;
        return 1;
    }

    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x1a) || opcode == UINT8_C(0x1b)
            || opcode == UINT8_C(0x5a) || opcode == UINT8_C(0x5b))) {
        shape->form = X86_EVEX_FORM_MEMORY_BROADCAST_BLOCK;
        shape->w = w;
        shape->element_bits = w != 0u ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK;
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66 && w == 0u
        && (opcode == UINT8_C(0x19) || opcode == UINT8_C(0x59))) {
        shape->form = X86_EVEX_FORM_QWORD_XMM_BROADCAST;
        shape->w = 0;
        shape->element_bits = 32;
        shape->flags = X86_EVEX_FLAG_MASK;
        return 1;
    }
    if (map_select == 3 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x1b) || opcode == UINT8_C(0x3b))) {
        shape->form = X86_EVEX_FORM_EXTRACT_HALF_IMM8;
        shape->w = w;
        shape->element_bits = w != 0u ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK;
        return 1;
    }
    if (map_select == 3 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x19) || opcode == UINT8_C(0x39))) {
        shape->form = X86_EVEX_FORM_EXTRACT_QUARTER_IMM8;
        shape->w = w;
        shape->element_bits = w != 0u ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK;
        return 1;
    }

    /* The complete packed narrowing rows are owned for all pp/W controls;
     * exact selector legality is published only after their full effective
     * address has been consumed. */
    if ((map_select == 1
            && (opcode == UINT8_C(0x63)
                || opcode == UINT8_C(0x67)
                || opcode == UINT8_C(0x6b)))
        || (map_select == 2 && opcode == UINT8_C(0x2b))) {
        const int dword_source = opcode == UINT8_C(0x6b)
            || map_select == 2;

        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = dword_source ? 0u : 2u;
        shape->element_bits = dword_source ? 32u : 16u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10
            | (dword_source ? X86_EVEX_FLAG_BROADCAST : 0u);
        return 1;
    }

    /* Opcode 68 owns both W-selected VP2INTERSECT forms for every prefix
     * selector.  Keep that structural ownership independent of the valid F2
     * selector so reserved encodings still consume their complete address. */
    if (map_select == 2 && opcode == UINT8_C(0x68)) {
        shape->form = X86_EVEX_FORM_MULTIDEST2;
        shape->w = w;
        shape->element_bits = w != 0 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_BROADCAST;
        return 1;
    }

    /* The four packed absolute-value opcode rows are structurally owned for
     * every pp/W control so a truncated effective address wins over the
     * eventual reserved-control diagnosis. */
    if (map_select == 2
        && opcode >= UINT8_C(0x1c) && opcode <= UINT8_C(0x1f)) {
        shape->form = X86_EVEX_FORM_UNARY_VECTOR;
        shape->w = opcode <= UINT8_C(0x1d)
            ? UINT8_C(2)
            : (uint8_t)(opcode == UINT8_C(0x1f));
        shape->element_bits = opcode == UINT8_C(0x1c) ? 8u
            : opcode == UINT8_C(0x1d) ? 16u
            : opcode == UINT8_C(0x1e) ? 32u : 64u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10;
        if (opcode >= UINT8_C(0x1e)) {
            shape->flags |= X86_EVEX_FLAG_BROADCAST;
        }
        return 1;
    }

    if (map_select == 6 && opcode == UINT8_C(0x42)
        && (prefix == X86_SIMD_PREFIX_NONE
            || prefix == X86_SIMD_PREFIX_P66)) {
        shape->form = X86_EVEX_FORM_UNARY_VECTOR;
        shape->w = 0;
        shape->element_bits = 16;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_AVX10;
        if (prefix == X86_SIMD_PREFIX_P66) {
            shape->flags |= X86_EVEX_FLAG_SAE;
        } else {
            shape->flags |= X86_EVEX_FLAG_AVX10_2;
        }
        return 1;
    }
    if (map_select == 6 && opcode == UINT8_C(0x43)
        && prefix == X86_SIMD_PREFIX_P66) {
        shape->form = X86_EVEX_FORM_NDS_SCALAR;
        shape->w = 0;
        shape->element_bits = 16;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_SAE
            | X86_EVEX_FLAG_AVX10;
        return 1;
    }

    if (map_select == 5 && opcode == UINT8_C(0x59)
        && (prefix == X86_SIMD_PREFIX_NONE
            || prefix == X86_SIMD_PREFIX_PF3)) {
        shape->form = prefix == X86_SIMD_PREFIX_PF3
            ? X86_EVEX_FORM_NDS_SCALAR : X86_EVEX_FORM_NDS_VECTOR;
        shape->w = 0;
        shape->element_bits = 16;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_ROUND
            | X86_EVEX_FLAG_AVX10;
        if (prefix == X86_SIMD_PREFIX_NONE) {
            shape->flags |= X86_EVEX_FLAG_BROADCAST;
        }
        return 1;
    }

    if (map_select == 5 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x58) || opcode == UINT8_C(0x59)
            || opcode == UINT8_C(0x5c) || opcode == UINT8_C(0x5e))) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = 0;
        shape->element_bits = 16;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_AVX10 | X86_EVEX_FLAG_AVX10_2;
        return 1;
    }

    if (map_select == 1 && opcode == UINT8_C(0x51)) {
        if (prefix == X86_SIMD_PREFIX_NONE
            || prefix == X86_SIMD_PREFIX_P66) {
            shape->form = X86_EVEX_FORM_UNARY_VECTOR;
            shape->w = prefix == X86_SIMD_PREFIX_P66 ? 1u : 0u;
            shape->element_bits = prefix == X86_SIMD_PREFIX_P66 ? 64u : 32u;
        } else {
            shape->form = X86_EVEX_FORM_NDS_SCALAR;
            shape->w = prefix == X86_SIMD_PREFIX_PF2 ? 1u : 0u;
            shape->element_bits = prefix == X86_SIMD_PREFIX_PF2 ? 64u : 32u;
        }
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_ROUND | X86_EVEX_FLAG_AVX10;
        if (shape->form == X86_EVEX_FORM_NDS_SCALAR) {
            shape->flags &= (uint8_t)~X86_EVEX_FLAG_BROADCAST;
        }
        return 1;
    }
    /* Conversion rows have other architecturally defined W/pp siblings.
     * Claim only the verified forms here so those siblings remain a bounded
     * UNSUPPORTED result rather than being mislabeled as reserved. */
    if (map_select == 1 && opcode == UINT8_C(0xe6)) {
        if (prefix == X86_SIMD_PREFIX_PF3 && w == 0) {
            shape->form = X86_EVEX_FORM_UNARY_WIDEN;
            shape->w = 0;
            shape->element_bits = 32;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
                | X86_EVEX_FLAG_B_IGNORED | X86_EVEX_FLAG_AVX10;
            return 1;
        }
        if ((prefix == X86_SIMD_PREFIX_P66
                || prefix == X86_SIMD_PREFIX_PF2)
            && w != 0) {
            shape->form = X86_EVEX_FORM_UNARY_NARROW;
            shape->w = 1;
            shape->element_bits = 64;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
                | (prefix == X86_SIMD_PREFIX_P66
                    ? X86_EVEX_FLAG_SAE : X86_EVEX_FLAG_ROUND)
                | X86_EVEX_FLAG_AVX10;
            return 1;
        }
        return 0;
    }
    if (map_select == 1 && opcode == UINT8_C(0x5b)) {
        if (w != 0 || (prefix != X86_SIMD_PREFIX_NONE
                && prefix != X86_SIMD_PREFIX_P66
                && prefix != X86_SIMD_PREFIX_PF3)) {
            return 0;
        }
        shape->form = X86_EVEX_FORM_UNARY_VECTOR;
        shape->w = 0;
        shape->element_bits = 32;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | (prefix == X86_SIMD_PREFIX_PF3
                ? X86_EVEX_FLAG_SAE : X86_EVEX_FLAG_ROUND)
            | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 1 && opcode == UINT8_C(0x5a)) {
        if (prefix == X86_SIMD_PREFIX_NONE && w == 0) {
            shape->form = X86_EVEX_FORM_UNARY_WIDEN;
            shape->w = 0;
            shape->element_bits = 32;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
                | X86_EVEX_FLAG_SAE | X86_EVEX_FLAG_AVX10;
            return 1;
        }
        if (prefix == X86_SIMD_PREFIX_P66 && w != 0) {
            shape->form = X86_EVEX_FORM_UNARY_NARROW;
            shape->w = 1;
            shape->element_bits = 64;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
                | X86_EVEX_FLAG_ROUND | X86_EVEX_FLAG_AVX10;
            return 1;
        }
        if (prefix == X86_SIMD_PREFIX_PF2 && w != 0) {
            shape->form = X86_EVEX_FORM_NDS_SCALAR;
            shape->w = 1;
            shape->element_bits = 64;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_ROUND
                | X86_EVEX_FLAG_AVX10;
            return 1;
        }
        if (prefix == X86_SIMD_PREFIX_PF3 && w == 0) {
            shape->form = X86_EVEX_FORM_NDS_SCALAR;
            shape->w = 0;
            shape->element_bits = 32;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_SAE
                | X86_EVEX_FLAG_AVX10;
            return 1;
        }
        return 0;
    }

    if (map_select == 1 && opcode == UINT8_C(0x58)
        && prefix == X86_SIMD_PREFIX_NONE) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = 0;
        shape->element_bits = 32;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_ROUND | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 1 && opcode == UINT8_C(0x58)
        && prefix == X86_SIMD_PREFIX_P66) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = 1;
        shape->element_bits = 64;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_ROUND | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 1 && opcode == UINT8_C(0x56)) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = prefix == X86_SIMD_PREFIX_P66 ? 1u : 0u;
        shape->element_bits = prefix == X86_SIMD_PREFIX_P66 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 1 && opcode == UINT8_C(0x59)) {
        shape->form = prefix == X86_SIMD_PREFIX_NONE
                || prefix == X86_SIMD_PREFIX_P66
            ? X86_EVEX_FORM_NDS_VECTOR
            : X86_EVEX_FORM_NDS_SCALAR;
        shape->w = prefix == X86_SIMD_PREFIX_P66
                || prefix == X86_SIMD_PREFIX_PF2
            ? 1u : 0u;
        shape->element_bits = shape->w != 0 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_ROUND | X86_EVEX_FLAG_AVX10;
        if (shape->form == X86_EVEX_FORM_NDS_SCALAR) {
            shape->flags &= (uint8_t)~X86_EVEX_FLAG_BROADCAST;
        }
        return 1;
    }
    if (map_select == 1 && opcode == UINT8_C(0x5c)
        && (prefix == X86_SIMD_PREFIX_NONE
            || prefix == X86_SIMD_PREFIX_P66)) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = prefix == X86_SIMD_PREFIX_P66 ? 1u : 0u;
        shape->element_bits = prefix == X86_SIMD_PREFIX_P66 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_ROUND | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 1 && opcode == UINT8_C(0x5e)
        && (prefix == X86_SIMD_PREFIX_NONE
            || prefix == X86_SIMD_PREFIX_P66)) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = prefix == X86_SIMD_PREFIX_P66 ? 1u : 0u;
        shape->element_bits = prefix == X86_SIMD_PREFIX_P66 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_ROUND | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 1 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0xd4)
            || opcode == UINT8_C(0xd8)
            || opcode == UINT8_C(0xd9)
            || opcode == UINT8_C(0xdc)
            || opcode == UINT8_C(0xdd)
            || opcode == UINT8_C(0xe8)
            || opcode == UINT8_C(0xe9)
            || opcode == UINT8_C(0xec)
            || opcode == UINT8_C(0xed)
            || (opcode >= UINT8_C(0xf8)
                && opcode <= UINT8_C(0xfe)))) {
        const int byte_element = opcode == UINT8_C(0xf8)
            || opcode == UINT8_C(0xfc)
            || opcode == UINT8_C(0xd8)
            || opcode == UINT8_C(0xdc)
            || opcode == UINT8_C(0xe8)
            || opcode == UINT8_C(0xec);
        const int word_element = opcode == UINT8_C(0xf9)
            || opcode == UINT8_C(0xfd)
            || opcode == UINT8_C(0xd9)
            || opcode == UINT8_C(0xdd)
            || opcode == UINT8_C(0xe9)
            || opcode == UINT8_C(0xed);

        shape->form = X86_EVEX_FORM_PACKED_INTEGER_ADD_SUB;
        shape->w = byte_element || word_element ? 2u
            : opcode == UINT8_C(0xfa) || opcode == UINT8_C(0xfe)
                ? 0u : 1u;
        shape->element_bits = byte_element ? 8u
            : word_element ? 16u
            : shape->w != 0 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10
            | (shape->element_bits >= 32u
                ? X86_EVEX_FLAG_BROADCAST : 0u);
        return 1;
    }
    if (map_select == 1 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0xdb)
            || opcode == UINT8_C(0xdf)
            || opcode == UINT8_C(0xeb)
            || opcode == UINT8_C(0xef))) {
        shape->form = X86_EVEX_FORM_PACKED_INTEGER_LOGICAL;
        shape->w = w;
        shape->element_bits = w != 0 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 1 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0xe0) || opcode == UINT8_C(0xe3))) {
        shape->form = X86_EVEX_FORM_PACKED_INTEGER_AVERAGE;
        shape->w = 2;
        shape->element_bits = opcode == UINT8_C(0xe0) ? 8u : 16u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 1 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x71) || opcode == UINT8_C(0x72)
            || opcode == UINT8_C(0x73))) {
        shape->form =
            X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE;
        if (opcode == UINT8_C(0x71)) {
            shape->w = 2;
            shape->element_bits = 16u;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10;
        } else if (opcode == UINT8_C(0x73)) {
            shape->w = 2;
            shape->element_bits = 8u;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10;
        } else {
            shape->w = w;
            shape->element_bits = w != 0 ? 64u : 32u;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
                | X86_EVEX_FLAG_AVX10;
        }
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x14)
            || opcode == UINT8_C(0x15)
            || opcode == UINT8_C(0x45)
            || opcode == UINT8_C(0x46)
            || opcode == UINT8_C(0x47))) {
        shape->form = X86_EVEX_FORM_PACKED_INTEGER_VARIABLE_SHIFT;
        shape->w = w;
        shape->element_bits = w != 0 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x10)
            || opcode == UINT8_C(0x11)
            || opcode == UINT8_C(0x12))) {
        shape->form = X86_EVEX_FORM_PACKED_INTEGER_VARIABLE_SHIFT;
        shape->w = 1;
        shape->element_bits = 16;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if ((map_select == 2 || map_select == 3)
        && prefix == X86_SIMD_PREFIX_P66
        && opcode >= UINT8_C(0x70) && opcode <= UINT8_C(0x73)) {
        const int dq_form = (opcode & UINT8_C(0x01)) != 0;

        shape->form = map_select == 2
            ? X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
            : X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE;
        shape->w = dq_form ? w : 1u;
        shape->element_bits = dq_form ? (w != 0 ? 64u : 32u) : 16u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10
            | (dq_form ? X86_EVEX_FLAG_BROADCAST : 0u);
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x62)
            || opcode == UINT8_C(0x63)
            || opcode == UINT8_C(0x88)
            || opcode == UINT8_C(0x89)
            || opcode == UINT8_C(0x8a)
            || opcode == UINT8_C(0x8b))) {
        const int byte_or_word = opcode == UINT8_C(0x62)
            || opcode == UINT8_C(0x63);

        shape->form = opcode == UINT8_C(0x63)
                || opcode == UINT8_C(0x8a)
                || opcode == UINT8_C(0x8b)
            ? X86_EVEX_FORM_COMPRESS : X86_EVEX_FORM_EXPAND;
        shape->w = w;
        shape->element_bits = byte_or_word
            ? (w != 0 ? 16u : 8u)
            : (w != 0 ? 64u : 32u);
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x44) || opcode == UINT8_C(0x54)
            || opcode == UINT8_C(0x55) || opcode == UINT8_C(0xc4))) {
        const int dword_or_qword = opcode != UINT8_C(0x54);

        shape->form = X86_EVEX_FORM_POPCOUNT;
        shape->w = w;
        shape->element_bits = dword_or_qword
            ? (w != 0 ? 64u : 32u)
            : (w != 0 ? 16u : 8u);
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10
            | (dword_or_qword ? X86_EVEX_FLAG_BROADCAST : 0u);
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_PF3
        && (opcode == UINT8_C(0x2a) || opcode == UINT8_C(0x3a))) {
        shape->form = X86_EVEX_FORM_MASK_BROADCAST;
        shape->w = opcode == UINT8_C(0x2a) ? 1u : 0u;
        shape->element_bits = opcode == UINT8_C(0x2a) ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && opcode == UINT8_C(0x8f)) {
        shape->form = X86_EVEX_FORM_BITALG_MASK_DESTINATION;
        shape->w = 0;
        shape->element_bits = 8;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66) {
        if (opcode == UINT8_C(0x75)
                || opcode == UINT8_C(0x7d)
                || opcode == UINT8_C(0x8d)) {
            shape->form = X86_EVEX_FORM_PERMUTE_TERNARY;
            shape->w = w;
            shape->element_bits = w != 0 ? 16u : 8u;
            shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10;
            return 1;
        }
        if (opcode == UINT8_C(0x83)) {
            shape->form = X86_EVEX_FORM_PERMUTE_TERNARY;
            shape->w = 1;
            shape->element_bits = 64;
            shape->flags = X86_EVEX_FLAG_MASK
                | X86_EVEX_FLAG_BROADCAST | X86_EVEX_FLAG_AVX10;
            return 1;
        }
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && opcode >= UINT8_C(0x50) && opcode <= UINT8_C(0x53)) {
        shape->form = X86_EVEX_FORM_VNNI_DOT_PRODUCT;
        shape->w = 0;
        shape->element_bits = 32;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 2 && prefix != X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x50) || opcode == UINT8_C(0x51))) {
        shape->form = X86_EVEX_FORM_VNNI_DOT_PRODUCT;
        shape->w = 0;
        shape->element_bits = 32;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_AVX10 | X86_EVEX_FLAG_AVX10_2;
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_PF2
        && (opcode == UINT8_C(0x52) || opcode == UINT8_C(0x53))) {
        shape->form = X86_EVEX_FORM_4VNNIW;
        shape->w = 0;
        shape->element_bits = 32;
        shape->flags = X86_EVEX_FLAG_MASK;
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_PF2
        && (opcode == UINT8_C(0x9a) || opcode == UINT8_C(0x9b)
            || opcode == UINT8_C(0xaa) || opcode == UINT8_C(0xab))) {
        const int scalar = (opcode & UINT8_C(0x01)) != 0;

        shape->form = scalar
            ? X86_EVEX_FORM_4FMAPS_SCALAR
            : X86_EVEX_FORM_4FMAPS_PACKED;
        shape->w = 0;
        shape->element_bits = 32;
        shape->flags = X86_EVEX_FLAG_MASK;
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x42) || opcode == UINT8_C(0x43))) {
        shape->form = opcode == UINT8_C(0x42)
            ? X86_EVEX_FORM_UNARY_VECTOR : X86_EVEX_FORM_NDS_SCALAR;
        shape->w = w;
        shape->element_bits = w != 0 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_SAE
            | X86_EVEX_FLAG_AVX10;
        if (opcode == UINT8_C(0x42)) {
            shape->flags |= X86_EVEX_FLAG_BROADCAST;
        }
        return 1;
    }
    if (map_select == 2
        && (opcode == UINT8_C(0xb4) || opcode == UINT8_C(0xb5))
        && prefix == X86_SIMD_PREFIX_P66) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = 1;
        shape->element_bits = 64;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST;
        return 1;
    }
    if (map_select == 2
        && opcode >= UINT8_C(0xdc) && opcode <= UINT8_C(0xdf)
        && prefix == X86_SIMD_PREFIX_P66) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = 2;
        shape->element_bits = 128;
        shape->flags = X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 2 && opcode == UINT8_C(0xda)
        && (prefix == X86_SIMD_PREFIX_PF2
            || prefix == X86_SIMD_PREFIX_PF3)) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = 0;
        shape->element_bits = 32;
        shape->flags = X86_EVEX_FLAG_AVX10
            | X86_EVEX_FLAG_AVX10_2;
        return 1;
    }
    if (map_select == 3 && opcode == UINT8_C(0x44)
        && prefix == X86_SIMD_PREFIX_P66) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR_IMM8;
        shape->w = 2;
        shape->element_bits = 64;
        shape->flags = X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 3 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x1e) || opcode == UINT8_C(0x1f)
            || opcode == UINT8_C(0x3e) || opcode == UINT8_C(0x3f))) {
        const int byte_or_word = opcode >= UINT8_C(0x3e);

        shape->form = X86_EVEX_FORM_COMPARE_MASK_IMM8;
        shape->w = w;
        shape->element_bits = byte_or_word
            ? (w != 0 ? 16u : 8u)
            : (w != 0 ? 64u : 32u);
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10
            | (byte_or_word ? 0u : X86_EVEX_FLAG_BROADCAST);
        return 1;
    }
    /* AVX512-FP16 VCMPPH is the floating-point sibling of the packed
     * integer compare matrix above.  It keeps W=0 and uses the same mask
     * destination/imm8 operand shape for XMM, YMM, and ZMM. */
    if (map_select == 3 && prefix == X86_SIMD_PREFIX_P66
        && opcode == UINT8_C(0xc2) && w == 0u) {
        shape->form = X86_EVEX_FORM_COMPARE_MASK_IMM8;
        shape->w = 0;
        shape->element_bits = 16;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (prefix == X86_SIMD_PREFIX_P66
        && ((map_select == 1
                && (opcode == UINT8_C(0xda)
                    || opcode == UINT8_C(0xde)
                    || opcode == UINT8_C(0xea)
                    || opcode == UINT8_C(0xee)))
            || (map_select == 2
                && opcode >= UINT8_C(0x38)
                && opcode <= UINT8_C(0x3f)))) {
        const int byte_element = opcode == UINT8_C(0xda)
            || opcode == UINT8_C(0xde)
            || opcode == UINT8_C(0x38)
            || opcode == UINT8_C(0x3c);
        const int word_element = opcode == UINT8_C(0xea)
            || opcode == UINT8_C(0xee)
            || opcode == UINT8_C(0x3a)
            || opcode == UINT8_C(0x3e);

        shape->form = X86_EVEX_FORM_PACKED_INTEGER_MINMAX;
        shape->w = byte_element || word_element ? 2u : w;
        shape->element_bits = byte_element ? 8u
            : word_element ? 16u : w != 0 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10
            | (shape->element_bits >= 32u
                ? X86_EVEX_FLAG_BROADCAST : 0u);
        return 1;
    }
    if (prefix == X86_SIMD_PREFIX_P66
        && ((map_select == 1
                && (opcode == UINT8_C(0xd5)
                    || opcode == UINT8_C(0xe4)
                    || opcode == UINT8_C(0xe5)
                    || opcode == UINT8_C(0xf4)
                    || opcode == UINT8_C(0xf5)))
            || (map_select == 2
                && (opcode == UINT8_C(0x04)
                    || opcode == UINT8_C(0x0b)
                    || opcode == UINT8_C(0x28)
                    || opcode == UINT8_C(0x40))))) {
        const int dword_or_qword = opcode == UINT8_C(0x40);
        const int fixed_qword = opcode == UINT8_C(0xf4)
            || opcode == UINT8_C(0x28);
        const int dword_result = opcode == UINT8_C(0xf5);

        shape->form = X86_EVEX_FORM_PACKED_INTEGER_MULTIPLY;
        shape->w = dword_or_qword ? w : fixed_qword ? 1u : 2u;
        shape->element_bits = dword_or_qword
            ? (w != 0 ? 64u : 32u)
            : fixed_qword ? 64u : dword_result ? 32u : 16u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_AVX10
            | (dword_or_qword || fixed_qword
                ? X86_EVEX_FLAG_BROADCAST : 0u);
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x96) || opcode == UINT8_C(0x97)
            || opcode == UINT8_C(0x98) || opcode == UINT8_C(0x9a)
            || opcode == UINT8_C(0x9c) || opcode == UINT8_C(0x9e)
            || opcode == UINT8_C(0xa6) || opcode == UINT8_C(0xa7)
            || opcode == UINT8_C(0xa8) || opcode == UINT8_C(0xaa)
            || opcode == UINT8_C(0xac) || opcode == UINT8_C(0xae)
            || opcode == UINT8_C(0xb6) || opcode == UINT8_C(0xb7)
            || opcode == UINT8_C(0xb8) || opcode == UINT8_C(0xba)
            || opcode == UINT8_C(0xbc) || opcode == UINT8_C(0xbe))) {
        shape->form = X86_EVEX_FORM_NDS_VECTOR;
        shape->w = w;
        shape->element_bits = w != 0 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_BROADCAST
            | X86_EVEX_FLAG_ROUND | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    if (map_select == 2 && prefix == X86_SIMD_PREFIX_P66
        && (opcode == UINT8_C(0x99) || opcode == UINT8_C(0x9b)
            || opcode == UINT8_C(0x9d) || opcode == UINT8_C(0x9f)
            || opcode == UINT8_C(0xa9) || opcode == UINT8_C(0xab)
            || opcode == UINT8_C(0xad) || opcode == UINT8_C(0xaf)
            || opcode == UINT8_C(0xb9) || opcode == UINT8_C(0xbb)
            || opcode == UINT8_C(0xbd) || opcode == UINT8_C(0xbf))) {
        shape->form = X86_EVEX_FORM_NDS_SCALAR;
        shape->w = w;
        shape->element_bits = w != 0 ? 64u : 32u;
        shape->flags = X86_EVEX_FLAG_MASK | X86_EVEX_FLAG_ROUND
            | X86_EVEX_FLAG_AVX10;
        return 1;
    }
    return 0;
}

#if USE_EXTRA_OPCODES
static const x86_evex_descriptor *find_evex_descriptor(
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w,
    uint8_t form,
    uint8_t opcode_extension)
{
    size_t index;

    for (index = 0; index < sizeof(x86_evex_map) / sizeof(x86_evex_map[0]);
         ++index) {
        const x86_evex_descriptor *descriptor = &x86_evex_map[index];

        if (descriptor->map == map_select
            && descriptor->opcode == opcode
            && descriptor->prefix == prefix
            && (descriptor->w == 2 || descriptor->w == w)
            && descriptor->form == form
            && (descriptor->opcode_extension == UINT8_C(0xff)
                || descriptor->opcode_extension == opcode_extension)) {
            return descriptor;
        }
    }
    return NULL;
}
#endif

/* Decode the APX-F MSR_IMM immediate-selector routes. */
static int decode_msr_imm_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const int is_read = prefix == X86_SIMD_PREFIX_PF2;
    x86_modrm modrm;
    uint64_t immediate;

    if (map_select != UINT8_C(7) || opcode != UINT8_C(0xf6)) {
        return -1;
    }
    /* R, R4, and X are ignored because raw ModRM.reg is fixed at zero and
     * the operand is a register.  B and B4 independently select r0..r31. */
    decoder->rex = (p0 & UINT8_C(0x20)) == 0 ? UINT8_C(1) : 0;
    decoder->rex_present = 0;
    decoder->modrm_reg_high = 0;
    decoder->modrm_rm_high =
        (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!read_immediate_value(decoder, 32u, &immediate)) {
        return 0;
    }
    /* Intel ISE Programming Reference #319433-060 specifies EVEX.W0 here.
     * Reject XED 2026.08's generated-pattern W1 over-acceptance.  Validate
     * owned-family controls after consuming ModRM/addressing and imm32 so a
     * structurally owned but short encoding reports truncation first. */
    if (decoder->mode != CDISASM_MODE_64
        || (prefix != X86_SIMD_PREFIX_PF2
            && prefix != X86_SIMD_PREFIX_PF3)
        || (p1 & UINT8_C(0xfc)) != UINT8_C(0x7c)
        || p2 != UINT8_C(0x08)
        || !modrm.is_register || modrm.reg3 != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (decoder->cpu_id != CDISASM_CPU_X86) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)is_read;
    (void)immediate;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = is_read
        ? CDISASM_X86_NAME_RDMSR : CDISASM_X86_NAME_WRMSRNS;
    decoder->form_id = is_read ? UINT16_C(2573) : UINT16_C(8895);
    decoder_require_caps(decoder, X86_CAP_AMD64);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_MSR_IMM);
    decoder->groups |= CDISASM_GROUP_PRIVILEGED;
    if (is_read) {
        return add_register_operand_access(
                decoder, modrm.rm, 64u,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_immediate_value(decoder, 32u, immediate, 0);
    }
    return add_immediate_value(decoder, 32u, immediate, 0)
        && add_register_operand_access(
            decoder, modrm.rm, 64u, CDISASM_OPERAND_ACCESS_READ);
#endif
}

/* Decode the APX-F USER_MSR register- and immediate-selector routes. */
static int decode_user_msr_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const int has_immediate = map_select == UINT8_C(7);
    const int is_read = prefix == X86_SIMD_PREFIX_PF2;
    x86_modrm modrm;
    uint64_t immediate = 0;

    if ((map_select != UINT8_C(4) && !has_immediate)
        || opcode != UINT8_C(0xf8)
        || (map_select == UINT8_C(4)
            && prefix != X86_SIMD_PREFIX_PF2
            && prefix != X86_SIMD_PREFIX_PF3)) {
        return -1;
    }

    /* MAP4 F2/F3 F8 is split by ModRM.mod: register forms are USER_MSR,
     * while memory forms are APX_F_ENQCMD.  Leave the latter to the pinned
     * generated descriptor rather than turning an allocated collision into
     * an invalid USER_MSR form. */
    if (!has_immediate
        && decoder->position < decoder->code_size
        && (decoder->code[decoder->position] & UINT8_C(0xc0))
            != UINT8_C(0xc0)) {
        return -1;
    }
    if (!has_immediate && decoder->position >= decoder->code_size) {
        return decoder_fail(decoder, CDISASM_STATUS_TRUNCATED);
    }
    if (decoder->mode != CDISASM_MODE_64
        || (prefix != X86_SIMD_PREFIX_PF2
            && prefix != X86_SIMD_PREFIX_PF3)
        || (p1 & UINT8_C(0xfc)) != UINT8_C(0x7c)
        || p2 != UINT8_C(0x08)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->rex = 0;
    if (!has_immediate && (p0 & UINT8_C(0x80)) == 0) {
        decoder->rex |= UINT8_C(4);
    }
    if (!has_immediate && (p0 & UINT8_C(0x40)) == 0) {
        decoder->rex |= UINT8_C(2);
    }
    if ((p0 & UINT8_C(0x20)) == 0) {
        decoder->rex |= UINT8_C(1);
    }
    decoder->rex_present = 0;
    decoder->modrm_reg_high = !has_immediate
        && (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    decoder->modrm_rm_high =
        (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (has_immediate && !read_immediate_value(
            decoder, 32u, &immediate)) {
        return 0;
    }
    if (!modrm.is_register || (has_immediate && modrm.reg3 != 0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)is_read;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = is_read
        ? CDISASM_X86_NAME_URDMSR : CDISASM_X86_NAME_UWRMSR;
    if (has_immediate) {
        decoder->form_id = is_read ? UINT16_C(3356) : UINT16_C(3360);
    } else {
        decoder->form_id = is_read ? UINT16_C(3354) : UINT16_C(3358);
    }
    decoder_require_caps(decoder, X86_CAP_AMD64);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_USER_MSR);
    if (has_immediate) {
        if (is_read) {
            return add_register_operand_access(
                    decoder, modrm.rm, 64u,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_immediate_value(decoder, 32u, immediate, 0);
        }
        return add_immediate_value(decoder, 32u, immediate, 0)
            && add_register_operand_access(
                decoder, modrm.rm, 64u, CDISASM_OPERAND_ACCESS_READ);
    }
    if (is_read) {
        return add_register_operand_access(
                decoder, modrm.rm, 64u,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                decoder, modrm.reg, 64u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    return add_register_operand_access(
            decoder, modrm.reg, 64u, CDISASM_OPERAND_ACCESS_READ)
        && add_register_operand_access(
            decoder, modrm.rm, 64u, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_apx_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t opcode)
{
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0;
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t nf = (p2 & UINT8_C(0x04)) != 0;
    const uint8_t nd = (p2 & UINT8_C(0x10)) != 0;
    unsigned int destination = ((unsigned int)(~p1) >> 3) & 15u;
    cdisasm_x86_name_id alu_name = CDISASM_X86_NAME_NONE;
    int nf_allowed = 0;
    int reverse_sources = 0;
    x86_modrm modrm;
    int form;
    uint64_t immediate = 0;
    unsigned int immediate_bits = 0;

    if (opcode == UINT8_C(0xfc)) {
        /* APX-F RAO-INT is the memory-only MAP4 FC row.  Unlike the base
         * APX integer rows, all four pp values are operations and raw U=0
         * is legal: for a memory operand it supplies the inverted X4 bit.
         * EVEX.vvvv/V' and every P2 control are otherwise reserved. */
        if (decoder->mode != CDISASM_MODE_64
            || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)
            || p2 != UINT8_C(0x08)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }

        decoder->rex = (uint8_t)(w ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0) {
            decoder->rex |= 4u;
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            decoder->rex |= 2u;
        }
        if ((p0 & UINT8_C(0x20)) == 0) {
            decoder->rex |= 1u;
        }
        decoder->rex_present = 0;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high =
            (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (modrm.is_register) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = prefix == X86_SIMD_PREFIX_P66
            ? CDISASM_X86_NAME_AAND
            : prefix == X86_SIMD_PREFIX_PF2
                ? CDISASM_X86_NAME_AOR
                : prefix == X86_SIMD_PREFIX_PF3
                    ? CDISASM_X86_NAME_AXOR
                    : CDISASM_X86_NAME_AADD;
        decoder->form_id = (cdisasm_x86_form_id)(
            (prefix == X86_SIMD_PREFIX_P66
                ? UINT16_C(10)
                : prefix == X86_SIMD_PREFIX_PF2
                    ? UINT16_C(259)
                    : prefix == X86_SIMD_PREFIX_PF3
                        ? UINT16_C(265) : UINT16_C(4))
            + w);
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(
            decoder, CDISASM_X86_GROUP_APX_F_RAO_INT);
        return add_rm_operand(decoder, &modrm, w != 0 ? 64u : 32u, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ_WRITE)
            && add_register_operand_access(
                decoder, modrm.reg, w != 0 ? 64u : 32u,
                CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    /* The memory half of MAP4 F2/F3 F8 is ENQCMD/ENQCMDS, not USER_MSR.
     * Returning unsupported allows the exact APX_F_ENQCMD generated
     * descriptor to lower its operands and apply its independent family bit.
     * Register forms have already been consumed by decode_user_msr_evex(). */
    if (opcode == UINT8_C(0xf8)
        && (prefix == X86_SIMD_PREFIX_PF2
            || prefix == X86_SIMD_PREFIX_PF3)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x66)) {
        const int is_adcx = prefix == X86_SIMD_PREFIX_P66;
        const int is_adox = prefix == X86_SIMD_PREFIX_PF3;
        const unsigned int bits = w != 0 ? 64u : 32u;

        /* APX-F ADX uses MAP4 66 with pp selecting ADCX/ADOX.  U, NF,
         * zeroing, vector length, and masking are reserved; ND selects the
         * three-operand NDD form and EVEX.vvvv/V' names its destination. */
        if (!is_adcx && !is_adox) {
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        if (decoder->mode != CDISASM_MODE_64
            || (p1 & UINT8_C(0x04)) == 0
            || (p2 != UINT8_C(0x08) && p2 != UINT8_C(0x10))
            || (nd == 0 && destination != 0)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        destination += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;
        if (destination >= 32u) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }

        decoder->rex = (uint8_t)(w ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
        if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
        if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
        decoder->rex_present = 0;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high =
            (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
        if (!decode_modrm(decoder, &modrm)) return 0;

#if !USE_EXTRA_OPCODES
        (void)bits;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = is_adcx
            ? CDISASM_X86_NAME_ADCX : CDISASM_X86_NAME_ADOX;
        decoder_require_extra(decoder, CDISASM_X86_GROUP_ADX);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        if (nd != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
            decoder->form_id = (cdisasm_x86_form_id)(
                (is_adcx ? UINT16_C(16) : UINT16_C(148))
                + (w != 0 ? UINT16_C(4) : UINT16_C(0))
                + (modrm.is_register ? UINT16_C(0) : UINT16_C(1)));
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_ADX_N3);
            return add_register_operand_access(
                    decoder, destination, bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_register_operand_access(
                    decoder, modrm.reg, bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            (is_adcx ? UINT16_C(15) : UINT16_C(147))
            + (w != 0 ? UINT16_C(4) : UINT16_C(0))
            + (modrm.is_register ? UINT16_C(0) : UINT16_C(3)));
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_ADX);
        return add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_READ_WRITE)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    /* APX-F conditional compare/test (CCMP and CTEST) occupies the native
     * EVEX map-4 SCC rows.  The compact generated table owns the complete
     * register, memory, and immediate matrix; let it consume the encoding
     * instead of applying the ordinary APX integer-row legality below.
     *
     * The immediate forms share the ordinary APX group-1 (80/81/83) and
     * unary (F6/F7) opcodes.  Their fixed ModRM.reg=7 selector is the
     * architectural discriminator, so inspect that byte without consuming
     * it and delegate only those rows. */
    {
        int scc_immediate_selector = 0;
        int ctest_immediate_selector = 0;
        if (decoder->position < decoder->code_size) {
            const uint8_t next_modrm = decoder->code[decoder->position];
            const unsigned int next_reg = (next_modrm >> 3) & 7u;
            scc_immediate_selector = next_reg == 7u;
            /* CTEST immediate uses the two low ModRM.reg selectors.  The
             * ordinary APX unary rows use selectors 2..7 (including IDIV),
             * so only 0/1 can be delegated without stealing those forms. */
            ctest_immediate_selector = next_reg <= 1u;
        }
    if ((opcode >= UINT8_C(0x38) && opcode <= UINT8_C(0x3b))
        || ((opcode >= UINT8_C(0x84) && opcode <= UINT8_C(0x8f))
            && (p2 & UINT8_C(0x10)) == 0u)
        || ((opcode == UINT8_C(0x80)
                || opcode == UINT8_C(0x81)
                || opcode == UINT8_C(0x83))
            && scc_immediate_selector
            && (p2 & UINT8_C(0xf0)) == 0u)
        || ((opcode == UINT8_C(0xf6) || opcode == UINT8_C(0xf7))
            && ctest_immediate_selector
            && (p2 & UINT8_C(0xf0)) == 0u)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    }

    /* POP2P/PUSH2P are native APX NDD stack-pair forms.  The legacy APX
     * opcode switch below treats 8F/FF as ordinary POP/INC groups and
     * rejects W=1; hand the architecturally allocated W1+ND encodings to the
     * generated table before that legacy validation runs. */
    if ((opcode == UINT8_C(0x8f) || opcode == UINT8_C(0xff))
        && w != 0 && nd != 0 && (p1 & UINT8_C(0x04)) != 0
        /* XED's N3 stack-pair witnesses use P2=10h (ND=1, NF=0);
         * retain 18h as the reserved/zero-upper spelling accepted by the
         * generated table so optional-opcode-OFF builds still classify both
         * allocated shapes as unsupported rather than malformed. */
        && (p2 == UINT8_C(0x10) || p2 == UINT8_C(0x18))
        && decoder->position < decoder->code_size
        && (((opcode == UINT8_C(0x8f))
                && (decoder->code[decoder->position] & UINT8_C(0x38))
                    == UINT8_C(0x00))
            || ((opcode == UINT8_C(0xff))
                && (decoder->code[decoder->position] & UINT8_C(0x38))
                    == UINT8_C(0x30)))) {
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    if (opcode >= UINT8_C(0x40) && opcode <= UINT8_C(0x4f)
        && prefix <= X86_SIMD_PREFIX_P66) {
        static const cdisasm_x86_form_id form_base[16] = {
            UINT16_C(770), UINT16_C(754),
            UINT16_C(726), UINT16_C(742),
            UINT16_C(782), UINT16_C(766),
            UINT16_C(722), UINT16_C(738),
            UINT16_C(778), UINT16_C(762),
            UINT16_C(774), UINT16_C(758),
            UINT16_C(734), UINT16_C(750),
            UINT16_C(730), UINT16_C(746)
        };
        const unsigned int condition = opcode - UINT8_C(0x40);
        const int u = (p1 & UINT8_C(0x04)) != 0;
        const unsigned int bits = prefix == X86_SIMD_PREFIX_P66
            ? 16u : (w != 0 ? 64u : 32u);

        /* Native APX CFCMOV rows share this opcode window with the
         * handwritten APX NDD CMOV rows.  CFCMOV is distinguished by
         * ND=0 or NF=1; leave those forms to the generated descriptor
         * matrix and keep this compact handler for ND=1/NF=0 CMOV only. */
        if (p0 == UINT8_C(0xf4)) {
#if !USE_EXTRA_OPCODES
            /* CFCMOV is an optional APX form.  Preserve the public
             * EXTRA_OK contract in an opcode-disabled build even when the
             * legacy structural checks below would classify a descriptor as
             * malformed before the generated table is available. */
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
        if ((nd == 0 || nf != 0)
            && decoder->cpu_id == CDISASM_CPU_X86) {
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }

        if (decoder->mode != CDISASM_MODE_64 || nd == 0
            || (p2 & UINT8_C(0xf7)) != UINT8_C(0x10)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        destination += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;
        decoder->rex = (uint8_t)(w ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
        if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
        if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
        decoder->rex_present = 0;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high = u ? 0u : 16u;
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (u != modrm.is_register) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        (void)condition;
        (void)bits;
        (void)form_base;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = apx_move_condition_name[condition];
        decoder->groups |= CDISASM_GROUP_CONDITIONAL;
        decoder->form_id = (cdisasm_x86_form_id)(
            form_base[condition]
            + (modrm.is_register ? UINT16_C(0) : UINT16_C(1)));
        decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
        decoder_require_caps(decoder, X86_CAP_AMD64 | X86_CAP_P6);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_N3);
        return add_register_operand_access(
                decoder, destination, bits,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (opcode >= UINT8_C(0x40) && opcode <= UINT8_C(0x4f)
        && prefix == X86_SIMD_PREFIX_PF2) {
        static const cdisasm_x86_form_id form_base[16] = {
            UINT16_C(2941), UINT16_C(2917),
            UINT16_C(2875), UINT16_C(2899),
            UINT16_C(2960), UINT16_C(2935),
            UINT16_C(2869), UINT16_C(2893),
            UINT16_C(2954), UINT16_C(2929),
            UINT16_C(2947), UINT16_C(2923),
            UINT16_C(2887), UINT16_C(2911),
            UINT16_C(2881), UINT16_C(2905)
        };
        const unsigned int condition = opcode - UINT8_C(0x40);
        const int u = (p1 & UINT8_C(0x04)) != 0;

        /* APX N3 SETcc fixes vvvv/V', VL, z, NF, and aaa.  ND is the
         * zero-upper selector here (not NDD), and U distinguishes the
         * register encoding from memory where it supplies inverted X4. */
        if (decoder->mode != CDISASM_MODE_64
            || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)
            || (p2 != UINT8_C(0x08) && p2 != UINT8_C(0x18))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->rex = (uint8_t)(w ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
        if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
        if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
        decoder->rex_present = 0;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high = u ? 0u : 16u;
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (u != modrm.is_register) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        (void)condition;
        (void)form_base;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = apx_set_condition_name[condition];
        decoder->groups |= CDISASM_GROUP_CONDITIONAL;
        decoder->form_id = (cdisasm_x86_form_id)(
            form_base[condition]
            + (modrm.is_register ? UINT16_C(0) : UINT16_C(3))
            + (nd != 0 ? UINT16_C(1) : UINT16_C(0)));
        if (nd != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_ZU;
        }
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_N3);
        return add_rm_operand(decoder, &modrm, 8u, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_WRITE);
#endif
    }

    if (decoder->mode != CDISASM_MODE_64
        || ((p1 & UINT8_C(0x04)) == 0
            && decoder->position < decoder->code_size
            && (decoder->code[decoder->position] & UINT8_C(0xc0))
                == UINT8_C(0xc0))
        || prefix > 1
        || (p2 & UINT8_C(0xe3)) != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    destination += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;

    switch (opcode) {
        case UINT8_C(0x00):
        case UINT8_C(0x01):
            alu_name = CDISASM_X86_NAME_ADD;
            nf_allowed = 1;
            form = 1;
            break;
        case UINT8_C(0x02):
        case UINT8_C(0x03):
            alu_name = CDISASM_X86_NAME_ADD;
            nf_allowed = 1;
            reverse_sources = 1;
            form = 1;
            break;
        case UINT8_C(0x08):
        case UINT8_C(0x09):
            alu_name = CDISASM_X86_NAME_OR;
            nf_allowed = 1;
            form = 1;
            break;
        case UINT8_C(0x0a):
        case UINT8_C(0x0b):
            alu_name = CDISASM_X86_NAME_OR;
            nf_allowed = 1;
            reverse_sources = 1;
            form = 1;
            break;
        case UINT8_C(0x10):
        case UINT8_C(0x11):
            alu_name = CDISASM_X86_NAME_ADC;
            form = 1;
            break;
        case UINT8_C(0x12):
        case UINT8_C(0x13):
            alu_name = CDISASM_X86_NAME_ADC;
            reverse_sources = 1;
            form = 1;
            break;
        case UINT8_C(0x18):
        case UINT8_C(0x19):
            alu_name = CDISASM_X86_NAME_SBB;
            form = 1;
            break;
        case UINT8_C(0x1a):
        case UINT8_C(0x1b):
            alu_name = CDISASM_X86_NAME_SBB;
            reverse_sources = 1;
            form = 1;
            break;
        case UINT8_C(0x20):
        case UINT8_C(0x21):
            alu_name = CDISASM_X86_NAME_AND;
            nf_allowed = 1;
            form = 1;
            break;
        case UINT8_C(0x22):
        case UINT8_C(0x23):
            alu_name = CDISASM_X86_NAME_AND;
            nf_allowed = 1;
            reverse_sources = 1;
            form = 1;
            break;
        case UINT8_C(0x28):
        case UINT8_C(0x29):
            alu_name = CDISASM_X86_NAME_SUB;
            nf_allowed = 1;
            form = 1;
            break;
        case UINT8_C(0x2a):
        case UINT8_C(0x2b):
            alu_name = CDISASM_X86_NAME_SUB;
            nf_allowed = 1;
            reverse_sources = 1;
            form = 1;
            break;
        case UINT8_C(0x30):
        case UINT8_C(0x31):
            alu_name = CDISASM_X86_NAME_XOR;
            nf_allowed = 1;
            form = 1;
            break;
        case UINT8_C(0x32):
        case UINT8_C(0x33):
            alu_name = CDISASM_X86_NAME_XOR;
            nf_allowed = 1;
            reverse_sources = 1;
            form = 1;
            break;
        case UINT8_C(0xfe):
        case UINT8_C(0xff):
            form = 9;
            break;
        case UINT8_C(0x8f):
            form = 3;
            break;
        case UINT8_C(0xf9):
            form = 4;
            break;
        case UINT8_C(0xf8):
            form = 5;
            break;
        case UINT8_C(0xf6):
        case UINT8_C(0xf7):
            form = 6;
            break;
        case UINT8_C(0xaf):
            form = 7;
            break;
        case UINT8_C(0x69):
        case UINT8_C(0x6b):
            form = 8;
            break;
        case UINT8_C(0x80):
        case UINT8_C(0x81):
        case UINT8_C(0x83):
            form = 10;
            break;
        case UINT8_C(0xc0):
        case UINT8_C(0xc1):
        case UINT8_C(0xd0):
        case UINT8_C(0xd1):
        case UINT8_C(0xd2):
        case UINT8_C(0xd3):
            form = 11;
            break;
        case UINT8_C(0x24):
        case UINT8_C(0x2c):
        case UINT8_C(0xa5):
        case UINT8_C(0xad):
            form = 12;
            break;
        default:
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    if (form == 1) {
        if ((nf != 0 && !nf_allowed)
            || (nd == 0 && destination != 0)
            || (((opcode & UINT8_C(1)) == 0)
                && (w != 0 || prefix != 0))) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else if (form == 2 || form == 3) {
        if (!nd || w != 0 || nf != 0 || prefix != 0) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else if (form == 6) {
        if ((nd == 0 && destination != 0)
            || (opcode == UINT8_C(0xf6)
                && (w != 0 || prefix != 0))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else if (form == 7) {
        if (nd == 0 && destination != 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else if (form == 8) {
        if (destination != 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else if (form == 9 || form == 10 || form == 11 || form == 12) {
        /* Validity depends on the ModRM group decoded below. */
    } else if (nd || nf != 0 || destination != 0
        || (form == 4 && prefix != 0)
        || (form == 5 && prefix != 1)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->rex = (uint8_t)(w ? 8u : 0u);
    if ((p0 & UINT8_C(0x80)) == 0) {
        decoder->rex |= 4u;
    }
    if ((p0 & UINT8_C(0x40)) == 0) {
        decoder->rex |= 2u;
    }
    if ((p0 & UINT8_C(0x20)) == 0) {
        decoder->rex |= 1u;
    }
    decoder->rex_present = 0;
    decoder->modrm_reg_high = (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    decoder->modrm_rm_high = (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
    decoder->address_base_high = decoder->modrm_rm_high;
    decoder->address_index_high =
        (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }

    if (form == 9) {
        if (opcode == UINT8_C(0xff) && modrm.reg3 == 6u) {
            if (!nd || w != 0 || nf != 0 || prefix != 0
                || !modrm.is_register) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            form = 2;
        } else if (modrm.reg3 > 1u
            || (nd == 0 && destination != 0)
            || (opcode == UINT8_C(0xfe)
                && (w != 0 || prefix != 0))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    if (form == 10) {
        const int group_nf_allowed = modrm.reg3 == 0u
            || modrm.reg3 == 1u || modrm.reg3 == 4u
            || modrm.reg3 == 5u || modrm.reg3 == 6u;

        if (modrm.reg3 > 6u
            || (nf != 0 && !group_nf_allowed)
            || (nd == 0 && destination != 0)
            || (opcode == UINT8_C(0x80)
                && (w != 0 || prefix != 0))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    if (form == 11) {
        const int group_nf_allowed = modrm.reg3 != 2u
            && modrm.reg3 != 3u;
        const int byte_form = opcode == UINT8_C(0xc0)
            || opcode == UINT8_C(0xd0)
            || opcode == UINT8_C(0xd2);

        if ((nf != 0 && !group_nf_allowed)
            || (nd == 0 && destination != 0)
            || (byte_form && (w != 0 || prefix != 0))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    if (form == 12 && nd == 0 && destination != 0) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (form == 1) {
        if (destination >= 32) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else if ((form == 2 || form == 3)
        && (!modrm.is_register
            || modrm.reg3 != (form == 2 ? 6u : 0u))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    } else if (form == 6
        && modrm.reg3 != 2u && modrm.reg3 != 3u
        && modrm.reg3 != 4u && modrm.reg3 != 5u
        && modrm.reg3 != 6u && modrm.reg3 != 7u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    } else if (form == 6 && modrm.reg3 == 2u && nf != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    } else if (form == 6
        && modrm.reg3 != 2u && modrm.reg3 != 3u && nd != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    } else if ((form == 4 || form == 5) && modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (form == 8 || form == 10) {
        const unsigned int bits = w != 0
            ? 64u : (prefix == 1 ? 16u : 32u);
        immediate_bits = opcode == UINT8_C(0x6b)
                || opcode == UINT8_C(0x80)
                || opcode == UINT8_C(0x83)
            ? 8u : (bits == 64u ? 32u : bits);
        if (!read_immediate_value(
                decoder, immediate_bits, &immediate)) {
            return 0;
        }
    }
    if (form == 11
        && (opcode == UINT8_C(0xc0) || opcode == UINT8_C(0xc1))) {
        immediate_bits = 8u;
        if (!read_immediate_value(decoder, 8u, &immediate)) {
            return 0;
        }
    }
    if (form == 12
        && (opcode == UINT8_C(0x24) || opcode == UINT8_C(0x2c))) {
        immediate_bits = 8u;
        if (!read_immediate_value(decoder, 8u, &immediate)) {
            return 0;
        }
    }

#if !USE_EXTRA_OPCODES
    (void)destination;
    (void)alu_name;
    (void)reverse_sources;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder_require_caps(decoder, X86_CAP_AMD64);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);

    if (form == 1) {
        const unsigned int bits = (opcode & UINT8_C(1)) == 0
            ? 8u : (w != 0 ? 64u : (prefix == 1 ? 16u : 32u));

        if (nd != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
        }
        if (nf != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
        }
        if (nd != 0 || nf != 0) {
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_N3);
        }
        decoder->name_id = alu_name;
        if (nd == 0) {
            if (reverse_sources) {
                return add_register_operand_access(
                        decoder, modrm.reg, bits,
                        CDISASM_OPERAND_ACCESS_READ_WRITE)
                    && add_rm_operand(decoder, &modrm, bits, 1)
                    && set_last_operand_access(
                        decoder, CDISASM_OPERAND_ACCESS_READ);
            }
            return add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_register_operand_access(
                    decoder, modrm.reg, bits,
                    CDISASM_OPERAND_ACCESS_READ);
        }
        if (!add_register_operand_access(
                decoder, destination, bits,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (reverse_sources) {
            return add_register_operand_access(
                    decoder, modrm.reg, bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ)
            && add_register_operand_access(
                decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ);
    }

    if (form == 4) {
        const unsigned int bits = w != 0 ? 64u : 32u;

        decoder->name_id = CDISASM_X86_NAME_MOVDIRI;
        decoder_require_caps(decoder, X86_CAP_MOVDIRI);
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ);
    }
    if (form == 5) {
        decoder->name_id = CDISASM_X86_NAME_MOVDIR64B;
        decoder_require_caps(decoder, X86_CAP_MOVDIR64B);
        return add_movdir64b_operands(decoder, &modrm);
    }

    if (form == 6) {
        const int byte_form = opcode == UINT8_C(0xf6);
        const unsigned int bits = byte_form
            ? 8u : (w != 0 ? 64u : (prefix == 1 ? 16u : 32u));

        decoder->name_id = modrm.reg3 == 2u
            ? CDISASM_X86_NAME_NOT
            : modrm.reg3 == 3u
                ? CDISASM_X86_NAME_NEG
            : modrm.reg3 == 4u
                ? CDISASM_X86_NAME_MUL
                : modrm.reg3 == 5u
                    ? CDISASM_X86_NAME_IMUL
                : modrm.reg3 == 6u
                    ? CDISASM_X86_NAME_DIV : CDISASM_X86_NAME_IDIV;
        if (modrm.reg3 == 3u) {
            decoder->form_id = (cdisasm_x86_form_id)(
                nd != 0
                    ? (byte_form
                        ? (modrm.is_register ? UINT16_C(1826)
                                             : UINT16_C(1827))
                        : (modrm.is_register ? UINT16_C(1831)
                                             : UINT16_C(1832)))
                    : ((byte_form
                        ? (modrm.is_register ? UINT16_C(1824)
                                             : UINT16_C(1836))
                        : (modrm.is_register ? UINT16_C(1829)
                                             : UINT16_C(1839)))
                        + (nf != 0 ? UINT16_C(1) : UINT16_C(0))));
            if (nd != 0) {
                decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
            }
            if (nf != 0) {
                decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
            }
            if (nd != 0 || nf != 0) {
                decoder_require_extra(
                    decoder, CDISASM_X86_GROUP_APX_F_N3);
            }
            if (nd != 0) {
                return add_register_operand_access(
                        decoder, destination, bits,
                        CDISASM_OPERAND_ACCESS_WRITE)
                    && add_rm_operand(decoder, &modrm, bits, 1)
                    && set_last_operand_access(
                        decoder, CDISASM_OPERAND_ACCESS_READ);
            }
            return add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ_WRITE);
        }
        if (modrm.reg3 != 2u) {
            if (modrm.reg3 == 5u) {
                decoder->form_id = (cdisasm_x86_form_id)(
                    (byte_form
                        ? (modrm.is_register ? UINT16_C(1338)
                                             : UINT16_C(1368))
                        : (modrm.is_register ? UINT16_C(1341)
                                             : UINT16_C(1371)))
                    + (nf != 0 ? UINT16_C(1) : UINT16_C(0)));
                if (nf != 0) {
                    decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
                    decoder_require_extra(
                        decoder, CDISASM_X86_GROUP_APX_F_N3);
                }
                return add_rm_operand(decoder, &modrm, bits, 1)
                    && set_last_operand_access(
                        decoder, CDISASM_OPERAND_ACCESS_READ);
            }
            static const cdisasm_x86_form_id byte_reg_forms[3] = {
                UINT16_C(1810), UINT16_C(1119), UINT16_C(1326)
            };
            static const cdisasm_x86_form_id value_reg_forms[3] = {
                UINT16_C(1813), UINT16_C(1122), UINT16_C(1329)
            };
            static const cdisasm_x86_form_id byte_mem_forms[3] = {
                UINT16_C(1816), UINT16_C(1125), UINT16_C(1332)
            };
            static const cdisasm_x86_form_id value_mem_forms[3] = {
                UINT16_C(1819), UINT16_C(1128), UINT16_C(1335)
            };
            const unsigned int operation = modrm.reg3 == 4u
                ? 0u : (modrm.reg3 == 6u ? 1u : 2u);

            decoder->form_id = (cdisasm_x86_form_id)(
                (byte_form
                    ? (modrm.is_register
                        ? byte_reg_forms[operation]
                        : byte_mem_forms[operation])
                    : (modrm.is_register
                        ? value_reg_forms[operation]
                        : value_mem_forms[operation]))
                + (nf != 0 ? UINT16_C(1) : UINT16_C(0)));
            if (nf != 0) {
                decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
                decoder_require_extra(
                    decoder, CDISASM_X86_GROUP_APX_F_N3);
            }
            return add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            byte_form
                ? (nd != 0
                    ? (modrm.is_register ? UINT16_C(1871)
                                         : UINT16_C(1872))
                    : (modrm.is_register ? UINT16_C(1870)
                                         : UINT16_C(1880)))
                : (nd != 0
                    ? (modrm.is_register ? UINT16_C(1875)
                                         : UINT16_C(1876))
                    : (modrm.is_register ? UINT16_C(1874)
                                         : UINT16_C(1882))));
        if (nd != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_N3);
            return add_register_operand_access(
                    decoder, destination, bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ_WRITE);
    }

    if (form == 7) {
        const unsigned int bits = w != 0
            ? 64u : (prefix == 1 ? 16u : 32u);

        decoder->name_id = CDISASM_X86_NAME_IMUL;
        if (nd != 0) {
            decoder->form_id = (cdisasm_x86_form_id)(
                modrm.is_register ? UINT16_C(1346) : UINT16_C(1355));
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
            if (nf != 0) {
                decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
            }
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_N3);
            return add_register_operand_access(
                    decoder, destination, bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_register_operand_access(
                    decoder, modrm.reg, bits,
                    CDISASM_OPERAND_ACCESS_READ)
                && add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            (modrm.is_register ? UINT16_C(1344) : UINT16_C(1357))
            + (nf != 0 ? UINT16_C(1) : UINT16_C(0)));
        if (nf != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_N3);
        }
        return add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_READ_WRITE)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }

    if (form == 8) {
        const int immediate8 = opcode == UINT8_C(0x6b);
        const unsigned int bits = w != 0
            ? 64u : (prefix == 1 ? 16u : 32u);
        const cdisasm_x86_form_id base_form = (cdisasm_x86_form_id)(
            immediate8
                ? (modrm.is_register ? UINT16_C(1347) : UINT16_C(1359))
                : (modrm.is_register ? UINT16_C(1352) : UINT16_C(1364)));

        decoder->name_id = CDISASM_X86_NAME_IMUL;
        decoder->form_id = (cdisasm_x86_form_id)(
            base_form + (nd != 0 ? UINT16_C(2)
                                 : (nf != 0 ? UINT16_C(1) : UINT16_C(0))));
        if (nf != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
        }
        if (nd != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_ZU;
        }
        if (nf != 0 || nd != 0) {
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_N3);
        }
        return add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ)
            && add_immediate_value(
                decoder, immediate_bits,
                (immediate8 || bits == 64u)
                    ? (uint64_t)sign_extend(immediate, immediate_bits)
                    : immediate,
                (immediate8 || bits == 64u)
                    ? CDISASM_OPERAND_FLAG_SIGNED : 0u);
    }

    if (form == 9) {
        const int byte_form = opcode == UINT8_C(0xfe);
        const int is_dec = modrm.reg3 != 0u;
        const unsigned int bits = byte_form
            ? 8u : (w != 0 ? 64u : (prefix == 1 ? 16u : 32u));
        const cdisasm_x86_form_id register_base = (cdisasm_x86_form_id)(
            is_dec ? (byte_form ? UINT16_C(1092) : UINT16_C(1097))
                   : (byte_form ? UINT16_C(1376) : UINT16_C(1381)));
        const cdisasm_x86_form_id memory_base = (cdisasm_x86_form_id)(
            is_dec ? (byte_form ? UINT16_C(1105) : UINT16_C(1108))
                   : (byte_form ? UINT16_C(1389) : UINT16_C(1392)));

        decoder->name_id = is_dec
            ? CDISASM_X86_NAME_DEC : CDISASM_X86_NAME_INC;
        if (nd != 0) {
            decoder->form_id = (cdisasm_x86_form_id)(
                is_dec
                    ? (byte_form
                        ? (modrm.is_register ? UINT16_C(1094)
                                             : UINT16_C(1095))
                        : (modrm.is_register ? UINT16_C(1100)
                                             : UINT16_C(1101)))
                    : (byte_form
                        ? (modrm.is_register ? UINT16_C(1378)
                                             : UINT16_C(1379))
                        : (modrm.is_register ? UINT16_C(1384)
                                             : UINT16_C(1385))));
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
        } else {
            decoder->form_id = (cdisasm_x86_form_id)(
                (modrm.is_register ? register_base : memory_base)
                + (nf != 0 ? UINT16_C(1) : UINT16_C(0)));
        }
        if (nf != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
        }
        if (nd != 0 || nf != 0) {
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_N3);
        }
        if (nd != 0) {
            return add_register_operand_access(
                    decoder, destination, bits,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ_WRITE);
    }

    if (form == 10) {
        static const cdisasm_x86_name_id group_names[7] = {
            CDISASM_X86_NAME_ADD, CDISASM_X86_NAME_OR,
            CDISASM_X86_NAME_ADC, CDISASM_X86_NAME_SBB,
            CDISASM_X86_NAME_AND, CDISASM_X86_NAME_SUB,
            CDISASM_X86_NAME_XOR
        };
        const unsigned int bits = opcode == UINT8_C(0x80)
            ? 8u : (w != 0 ? 64u : (prefix == 1 ? 16u : 32u));
        const int signed_immediate = opcode == UINT8_C(0x83)
            || (opcode == UINT8_C(0x81) && bits == 64u);

        decoder->name_id = group_names[modrm.reg3];
        if (nd != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
        }
        if (nf != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
        }
        if (nd != 0 || nf != 0) {
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_N3);
        }
        if (nd != 0
            && !add_register_operand_access(
                decoder, destination, bits,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (!add_rm_operand(decoder, &modrm, bits, 1)
            || !set_last_operand_access(
                decoder, nd != 0
                    ? CDISASM_OPERAND_ACCESS_READ
                    : CDISASM_OPERAND_ACCESS_READ_WRITE)) {
            return 0;
        }
        return add_immediate_value(
            decoder, immediate_bits,
            signed_immediate
                ? (uint64_t)sign_extend(immediate, immediate_bits)
                : immediate,
            signed_immediate ? CDISASM_OPERAND_FLAG_SIGNED : 0u);
    }

    if (form == 11) {
        static const cdisasm_x86_name_id group_names[8] = {
            CDISASM_X86_NAME_ROL, CDISASM_X86_NAME_ROR,
            CDISASM_X86_NAME_RCL, CDISASM_X86_NAME_RCR,
            CDISASM_X86_NAME_SHL, CDISASM_X86_NAME_SHR,
            CDISASM_X86_NAME_SHL, CDISASM_X86_NAME_SAR
        };
        const int byte_form = opcode == UINT8_C(0xc0)
            || opcode == UINT8_C(0xd0)
            || opcode == UINT8_C(0xd2);
        const unsigned int bits = byte_form
            ? 8u : (w != 0 ? 64u : (prefix == 1 ? 16u : 32u));

        decoder->name_id = group_names[modrm.reg3];
        if (nd != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
        }
        if (nf != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
        }
        if (nd != 0 || nf != 0) {
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_N3);
        }
        if (nd != 0
            && !add_register_operand_access(
                decoder, destination, bits,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (!add_rm_operand(decoder, &modrm, bits, 1)
            || !set_last_operand_access(
                decoder, nd != 0
                    ? CDISASM_OPERAND_ACCESS_READ
                    : CDISASM_OPERAND_ACCESS_READ_WRITE)) {
            return 0;
        }
        if (opcode == UINT8_C(0xc0) || opcode == UINT8_C(0xc1)) {
            return add_immediate_value(decoder, 8u, immediate, 0u);
        }
        if (opcode == UINT8_C(0xd0) || opcode == UINT8_C(0xd1)) {
            return add_immediate_value(
                decoder, 0u, 1u, CDISASM_OPERAND_FLAG_IMPLICIT);
        }
        return add_named_register_operand(
            decoder, CDISASM_REG_CL, 8u,
            CDISASM_OPERAND_FLAG_IMPLICIT);
    }

    if (form == 12) {
        const int is_shrd = opcode == UINT8_C(0x2c)
            || opcode == UINT8_C(0xad);
        const int immediate_count = opcode == UINT8_C(0x24)
            || opcode == UINT8_C(0x2c);
        const unsigned int bits = w != 0
            ? 64u : (prefix == 1 ? 16u : 32u);

        decoder->name_id = is_shrd
            ? CDISASM_X86_NAME_SHRD : CDISASM_X86_NAME_SHLD;
        if (nd != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
        }
        if (nf != 0) {
            decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
        }
        if (nd != 0 || nf != 0) {
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_APX_F_N3);
        }
        if (nd != 0
            && !add_register_operand_access(
                decoder, destination, bits,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (!add_rm_operand(decoder, &modrm, bits, 1)
            || !set_last_operand_access(
                decoder, nd != 0
                    ? CDISASM_OPERAND_ACCESS_READ
                    : CDISASM_OPERAND_ACCESS_READ_WRITE)
            || !add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
        return immediate_count
            ? add_immediate_value(decoder, 8u, immediate, 0u)
            : add_named_register_operand(
                decoder, CDISASM_REG_CL, 8u,
                CDISASM_OPERAND_FLAG_IMPLICIT);
    }

    decoder->name_id = form == 2
        ? CDISASM_X86_NAME_PUSH2
        : CDISASM_X86_NAME_POP2;
    decoder->prefix_flags |= CDISASM_PREFIX_APX_NDD;
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_N3);
    return add_register_operand_access(
            decoder, destination, 64u,
            form == 2 ? CDISASM_OPERAND_ACCESS_READ
                      : CDISASM_OPERAND_ACCESS_WRITE)
        && add_register_operand_access(
            decoder, modrm.rm, 64u,
            form == 2 ? CDISASM_OPERAND_ACCESS_READ
                      : CDISASM_OPERAND_ACCESS_WRITE);
#endif
}

typedef struct x86_amx_row_descriptor {
    cdisasm_x86_name_id name_id;
    uint8_t map;
    uint8_t opcode;
    uint8_t prefix;
    uint8_t immediate;
} x86_amx_row_descriptor;

typedef struct x86_ace_tilemov_descriptor {
    cdisasm_x86_name_id name_id;
    uint8_t map;
    uint8_t opcode;
    uint8_t immediate;
} x86_ace_tilemov_descriptor;

static const x86_ace_tilemov_descriptor x86_ace_tilemov_map[] = {
    {CDISASM_X86_NAME_TILEMOVROW, 2, 0x4a, 0},
    {CDISASM_X86_NAME_TILEMOVCOL, 2, 0x4b, 0},
    {CDISASM_X86_NAME_TILEMOVROW, 3, 0x07, 1},
    {CDISASM_X86_NAME_TILEMOVCOL, 3, 0x2f, 1}
};

/* Return -1 when the tuple is outside ACE's BSR state-transfer row. */
static int decode_ace_bsr_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w,
    uint8_t ll,
    uint8_t aaa)
{
    unsigned int source_index;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(6) || opcode != UINT8_C(0x95)) {
        return -1;
    }
    source_index = ((unsigned int)(~p1) >> 3) & 15u;
    source_index += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;
    if (decoder->mode != CDISASM_MODE_64
        || (p1 & UINT8_C(0x04)) == 0 || ll != 2 || aaa != 0
        || (p2 & UINT8_C(0xd0)) != UINT8_C(0x40)
        || (p0 & UINT8_C(0x90)) != UINT8_C(0x90)
        || prefix == X86_SIMD_PREFIX_P66
        || (prefix == X86_SIMD_PREFIX_NONE && w == 0)
        || (prefix != X86_SIMD_PREFIX_NONE && source_index != 0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->rex = 0;
    if ((p0 & UINT8_C(0x40)) == 0) {
        decoder->rex |= UINT8_C(2);
    }
    if ((p0 & UINT8_C(0x20)) == 0) {
        decoder->rex |= UINT8_C(1);
    }
    decoder->rex_present = 0;
    decoder->modrm_reg_high = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.reg3 != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (modrm.is_register && (p0 & UINT8_C(0x40)) == 0) {
        modrm.rm = (uint8_t)(modrm.rm + 16u);
    }

    if (prefix == X86_SIMD_PREFIX_NONE) {
        name_id = CDISASM_X86_NAME_BSRMOVF;
        form_id = modrm.is_register ? UINT16_C(380) : UINT16_C(379);
    } else if (prefix == X86_SIMD_PREFIX_PF2) {
        name_id = CDISASM_X86_NAME_BSRMOVH;
        form_id = w != 0
            ? (modrm.is_register ? UINT16_C(382) : UINT16_C(381))
            : (modrm.is_register ? UINT16_C(384) : UINT16_C(383));
    } else if (prefix == X86_SIMD_PREFIX_PF3) {
        name_id = CDISASM_X86_NAME_BSRMOVL;
        form_id = w != 0
            ? (modrm.is_register ? UINT16_C(386) : UINT16_C(385))
            : (modrm.is_register ? UINT16_C(388) : UINT16_C(387));
    } else {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AMD64);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_ACE_1);
    if (prefix == X86_SIMD_PREFIX_NONE) {
        return add_named_register_operand(
                decoder, CDISASM_X86_REG_BSR0, 1024u,
                CDISASM_OPERAND_FLAG_IMPLICIT)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                decoder, source_index, 512u,
                CDISASM_OPERAND_ACCESS_READ)
            && add_vector_rm_operand_access(
                decoder, &modrm, 512u, 512u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (w != 0) {
        return add_named_register_operand(
                decoder, CDISASM_X86_REG_BSR0, 1024u,
                CDISASM_OPERAND_FLAG_IMPLICIT)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_rm_operand_access(
                decoder, &modrm, 512u, 512u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_rm_operand_access(
            decoder, &modrm, 512u, 512u,
            CDISASM_OPERAND_ACCESS_WRITE)
        && add_named_register_operand(
            decoder, CDISASM_X86_REG_BSR0, 1024u,
            CDISASM_OPERAND_FLAG_IMPLICIT)
        && set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

/* Return -1 when the EVEX tuple is outside the ACE tile-move subset. */
static int decode_ace_tilemov_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w,
    uint8_t ll,
    uint8_t aaa)
{
    const x86_ace_tilemov_descriptor *descriptor = NULL;
    unsigned int source_index;
    x86_modrm modrm;
    uint64_t immediate = 0;
    size_t index;

    if (w == 0) {
        return -1;
    }
    for (index = 0;
         index < sizeof(x86_ace_tilemov_map)
             / sizeof(x86_ace_tilemov_map[0]);
         ++index) {
        const x86_ace_tilemov_descriptor *candidate =
            &x86_ace_tilemov_map[index];

        if (candidate->map == map_select && candidate->opcode == opcode) {
            descriptor = candidate;
            break;
        }
    }
    if (descriptor == NULL) {
        return -1;
    }

    source_index = ((unsigned int)(~p1) >> 3) & 15u;
    source_index += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;
    if (decoder->mode != CDISASM_MODE_64
        || prefix != X86_SIMD_PREFIX_P66
        || ll != 2 || (p2 & UINT8_C(0x90)) != 0 || aaa != 0
        /* TMM_R3 has no R/R' extension; B'/X' extend ZMM_B3. */
        || (p0 & UINT8_C(0x90)) != UINT8_C(0x90)
        || (descriptor->immediate != 0 && source_index != 0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->rex = (p0 & UINT8_C(0x20)) == 0 ? UINT8_C(1) : 0;
    decoder->rex_present = 0;
    decoder->modrm_reg_high = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((p0 & UINT8_C(0x40)) == 0) {
        modrm.rm += 16u;
    }
    if (descriptor->immediate != 0
        && !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }

#if !USE_EXTRA_OPCODES
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = descriptor->name_id;
    decoder_require_extra(decoder, CDISASM_X86_GROUP_ACE_1);
    if ((p0 & UINT8_C(0x08)) != 0) {
        /* ACE accepts B4 as an optional APX extension bit even though this
         * register form does not consume it as part of ZMM_B3. */
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (!add_tile_register_operand_access(
            decoder, modrm.reg3, CDISASM_OPERAND_ACCESS_WRITE)
        || !add_vector_register_operand_access(
            decoder, modrm.rm, 512u, CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return descriptor->immediate != 0
        ? add_immediate_value(decoder, 8u, immediate, 0)
        : add_register_operand_access(
            decoder, source_index, 32u, CDISASM_OPERAND_ACCESS_READ);
#endif
}

typedef struct x86_ace_top_descriptor {
    cdisasm_x86_name_id name_id;
    uint8_t map;
    uint8_t opcode;
    uint8_t prefix;
    uint8_t immediate;
} x86_ace_top_descriptor;

static const x86_ace_top_descriptor x86_ace_top_map[] = {
    {CDISASM_X86_NAME_TOP2BF16PS, 2, 0x5c, X86_SIMD_PREFIX_PF3, 0},
    {CDISASM_X86_NAME_TOP4BSSD, 2, 0x5e, X86_SIMD_PREFIX_PF2, 0},
    {CDISASM_X86_NAME_TOP4BSUD, 2, 0x5e, X86_SIMD_PREFIX_PF3, 0},
    {CDISASM_X86_NAME_TOP4BUSD, 2, 0x5e, X86_SIMD_PREFIX_P66, 0},
    {CDISASM_X86_NAME_TOP4BUUD, 2, 0x5e, X86_SIMD_PREFIX_NONE, 0},
    {CDISASM_X86_NAME_TOP4MXBF8PS, 3, 0x8d, X86_SIMD_PREFIX_NONE, 1},
    {CDISASM_X86_NAME_TOP4MXBHF8PS, 3, 0x8d, X86_SIMD_PREFIX_PF2, 1},
    {CDISASM_X86_NAME_TOP4MXHBF8PS, 3, 0x8d, X86_SIMD_PREFIX_PF3, 1},
    {CDISASM_X86_NAME_TOP4MXHF8PS, 3, 0x8d, X86_SIMD_PREFIX_P66, 1},
    {CDISASM_X86_NAME_TOP4MXBSSPS, 3, 0x8f, X86_SIMD_PREFIX_PF2, 1}
};

/* Return -1 when the EVEX tuple is outside the ACE TOP2/TOP4 subset. */
static int decode_ace_top_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w,
    uint8_t ll,
    uint8_t aaa)
{
    const x86_ace_top_descriptor *descriptor = NULL;
    unsigned int source_index;
    x86_modrm modrm;
    uint64_t immediate = 0;
    size_t index;
    int owns_opcode = (map_select == 2
            && (opcode == UINT8_C(0x5c) || opcode == UINT8_C(0x5e)))
        || (map_select == 3
            && (opcode == UINT8_C(0x8d) || opcode == UINT8_C(0x8f)));

    if (!owns_opcode) {
        return -1;
    }
    for (index = 0;
         index < sizeof(x86_ace_top_map) / sizeof(x86_ace_top_map[0]);
         ++index) {
        const x86_ace_top_descriptor *candidate = &x86_ace_top_map[index];

        if (candidate->map == map_select
            && candidate->opcode == opcode
            && candidate->prefix == prefix) {
            descriptor = candidate;
            break;
        }
    }
    if (descriptor == NULL) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    source_index = ((unsigned int)(~p1) >> 3) & 15u;
    source_index += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;
    if (decoder->mode != CDISASM_MODE_64 || w != 0
        || (p1 & UINT8_C(0x04)) == 0
        || ll != 2 || (p2 & UINT8_C(0x90)) != 0 || aaa != 0
        /* TMM_R3 has no R/R' extension; B'/X' extend ZMM_B3. */
        || (p0 & UINT8_C(0x90)) != UINT8_C(0x90)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->rex = (p0 & UINT8_C(0x20)) == 0 ? UINT8_C(1) : 0;
    decoder->rex_present = 0;
    decoder->modrm_reg_high = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((p0 & UINT8_C(0x40)) == 0) {
        modrm.rm += 16u;
    }
    if (descriptor->immediate != 0
        && !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }

#if !USE_EXTRA_OPCODES
    (void)source_index;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = descriptor->name_id;
    decoder_require_extra(decoder, CDISASM_X86_GROUP_ACE_1);
    if ((p0 & UINT8_C(0x08)) != 0) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (!add_tile_register_operand_access(
            decoder, modrm.reg3, CDISASM_OPERAND_ACCESS_READ_WRITE)
        || !add_vector_register_operand_access(
            decoder, modrm.rm, 512u, CDISASM_OPERAND_ACCESS_READ)
        || !add_vector_register_operand_access(
            decoder, source_index, 512u, CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    /* XED's BSR0 operand is suppressed state and intentionally absent from
     * the public syntax/operand list; the explicit imm8 remains visible. */
    return descriptor->immediate == 0
        || add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static const x86_amx_row_descriptor x86_amx_row_map[] = {
    {CDISASM_X86_NAME_TCVTROWD2PS, 2, 0x4a, X86_SIMD_PREFIX_PF3, 0},
    {CDISASM_X86_NAME_TILEMOVROW, 2, 0x4a, X86_SIMD_PREFIX_P66, 0},
    {CDISASM_X86_NAME_TCVTROWPS2BF16H, 2, 0x6d,
        X86_SIMD_PREFIX_PF2, 0},
    {CDISASM_X86_NAME_TCVTROWPS2BF16L, 2, 0x6d,
        X86_SIMD_PREFIX_PF3, 0},
    {CDISASM_X86_NAME_TCVTROWPS2PHH, 2, 0x6d,
        X86_SIMD_PREFIX_NONE, 0},
    {CDISASM_X86_NAME_TCVTROWPS2PHL, 2, 0x6d,
        X86_SIMD_PREFIX_P66, 0},
    {CDISASM_X86_NAME_TCVTROWD2PS, 3, 0x07, X86_SIMD_PREFIX_PF3, 1},
    {CDISASM_X86_NAME_TCVTROWPS2BF16H, 3, 0x07,
        X86_SIMD_PREFIX_PF2, 1},
    {CDISASM_X86_NAME_TCVTROWPS2PHH, 3, 0x07,
        X86_SIMD_PREFIX_NONE, 1},
    {CDISASM_X86_NAME_TILEMOVROW, 3, 0x07, X86_SIMD_PREFIX_P66, 1},
    {CDISASM_X86_NAME_TCVTROWPS2BF16L, 3, 0x77,
        X86_SIMD_PREFIX_PF3, 1},
    {CDISASM_X86_NAME_TCVTROWPS2PHL, 3, 0x77,
        X86_SIMD_PREFIX_PF2, 1}
};

/* Return -1 when the EVEX tuple is outside the AMX-AVX512 row subset. */
static int decode_amx_row_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode,
    uint8_t prefix,
    uint8_t w,
    uint8_t ll,
    uint8_t aaa)
{
    const x86_amx_row_descriptor *descriptor = NULL;
    unsigned int source_index;
    x86_modrm modrm;
    uint64_t immediate = 0;
    size_t index;

    for (index = 0;
         index < sizeof(x86_amx_row_map) / sizeof(x86_amx_row_map[0]);
         ++index) {
        const x86_amx_row_descriptor *candidate = &x86_amx_row_map[index];

        if (candidate->map == map_select
            && candidate->opcode == opcode
            && candidate->prefix == prefix) {
            descriptor = candidate;
            break;
        }
    }
    if (descriptor == NULL) {
        return -1;
    }

    source_index = ((unsigned int)(~p1) >> 3) & 15u;
    source_index += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;
    if (decoder->mode != CDISASM_MODE_64
        || ll != 2 || (p2 & UINT8_C(0x90)) != 0 || aaa != 0
        || (p0 & UINT8_C(0x68)) != UINT8_C(0x60) || w != 0
        || (descriptor->immediate != 0 && source_index != 0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->rex = 0;
    if ((p0 & UINT8_C(0x80)) == 0) {
        decoder->rex |= UINT8_C(4);
    }
    decoder->rex_present = 0;
    decoder->modrm_reg_high = (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!modrm.is_register || modrm.rm3 >= 8) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (descriptor->immediate != 0
        && !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }

#if !USE_EXTRA_OPCODES
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = descriptor->name_id;
    decoder_require_extra(decoder, CDISASM_X86_GROUP_AMX_TILE);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_AMX_AVX512);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, 512u, CDISASM_OPERAND_ACCESS_WRITE)
        || !add_tile_register_operand_access(
            decoder, modrm.rm3, CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return descriptor->immediate != 0
        ? add_immediate_value(decoder, 8u, immediate, 0)
        : add_register_operand_access(
            decoder, source_index, 32u, CDISASM_OPERAND_ACCESS_READ);
#endif
}

/* Return -1 when the tuple is outside APX's extended-address AMX subset. */
static int decode_apx_amx_memory_evex(
    x86_decoder *decoder,
    uint8_t p0, uint8_t p1, uint8_t p2,
    uint8_t map_select, uint8_t opcode, uint8_t prefix,
    uint8_t w, uint8_t ll, uint8_t aaa)
{
    cdisasm_x86_name_id name_id = CDISASM_X86_NAME_INVALID;
    cdisasm_x86_form_id form_id = 0;
    cdisasm_x86_group_id family_group = CDISASM_X86_GROUP_APX_F_AMX;
    int form = 0;
    x86_modrm modrm;

    if (map_select != UINT8_C(2)
        || (opcode != UINT8_C(0x49)
            && opcode != UINT8_C(0x4a)
            && opcode != UINT8_C(0x4b))
        || ((p0 & UINT8_C(0x08)) == 0
            && (p1 & UINT8_C(0x04)) != 0)) {
        return -1;
    }
    if (opcode == UINT8_C(0x49)) {
        if (prefix == X86_SIMD_PREFIX_NONE) {
            name_id = CDISASM_X86_NAME_LDTILECFG;
            form_id = UINT16_C(1578);
            form = 1;
        } else if (prefix == X86_SIMD_PREFIX_P66) {
            name_id = CDISASM_X86_NAME_STTILECFG;
            form_id = UINT16_C(3171);
            form = 2;
        }
        family_group = CDISASM_X86_GROUP_APX_F_AMX_BASE;
    } else if (opcode == UINT8_C(0x4a)) {
        if (prefix == X86_SIMD_PREFIX_PF2) {
            name_id = CDISASM_X86_NAME_TILELOADDRS;
            form_id = UINT16_C(3294);
            form = 3;
        } else if (prefix == X86_SIMD_PREFIX_P66) {
            name_id = CDISASM_X86_NAME_TILELOADDRST1;
            form_id = UINT16_C(3292);
            form = 3;
        }
        family_group = CDISASM_X86_GROUP_APX_F_AMX_MOVRS;
    } else if (prefix == X86_SIMD_PREFIX_PF2) {
        name_id = CDISASM_X86_NAME_TILELOADD;
        form_id = UINT16_C(3298);
        form = 3;
    } else if (prefix == X86_SIMD_PREFIX_P66) {
        name_id = CDISASM_X86_NAME_TILELOADDT1;
        form_id = UINT16_C(3296);
        form = 3;
    } else if (prefix == X86_SIMD_PREFIX_PF3) {
        name_id = CDISASM_X86_NAME_TILESTORED;
        form_id = UINT16_C(3307);
        form = 4;
    }
    if (form == 0) {
        return -1;
    }

    decoder->rex = 0;
    if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
    if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
    if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
    decoder->rex_present = 0;
    decoder->modrm_reg_high = (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    decoder->modrm_rm_high = (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
    decoder->address_base_high = decoder->modrm_rm_high;
    decoder->address_index_high = (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->mode != CDISASM_MODE_64 || w != 0 || ll != 0 || aaa != 0
        || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)
        || (p2 & UINT8_C(0x18)) != UINT8_C(0x08)
        || (p0 & UINT8_C(0x90)) != UINT8_C(0x90)
        || (opcode != UINT8_C(0x4a) && (p2 & UINT8_C(0x80)) != 0)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0
        || modrm.is_register || modrm.reg3 >= 8
        || (form <= 2 && modrm.reg3 != 0)
        || (form >= 3 && modrm.rm3 != 4)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    (void)family_group;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AMD64);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    decoder_require_extra(decoder, family_group);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_AMX_TILE);
    if (family_group == CDISASM_X86_GROUP_APX_F_AMX_MOVRS) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AMX_MOVRS);
    }
    if (form <= 2) {
        if (!add_rm_operand(decoder, &modrm, 512u, 0)) return 0;
        decoder->operand[decoder->operand_count - 1].flags |=
            CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        return set_last_operand_access(decoder,
            form == 1 ? CDISASM_OPERAND_ACCESS_READ
                      : CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (form == 3) {
        if (!add_tile_register_operand_access(
                decoder, modrm.reg3, CDISASM_OPERAND_ACCESS_WRITE)
            || !add_rm_operand(decoder, &modrm, 8u, 0)) return 0;
        decoder->operand[decoder->operand_count - 1].flags |=
            CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        return set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    if (!add_rm_operand(decoder, &modrm, 8u, 0)) return 0;
    decoder->operand[decoder->operand_count - 1].flags |=
        CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
    return set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_WRITE)
        && add_tile_register_operand_access(
            decoder, modrm.reg3, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int cpu_has_avx512f_width(
    cdisasm_x86_cpu_id cpu_id,
    unsigned int vector_bits)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_SKYLAKE_SP:
        case CDISASM_CPU_ICE_LAKE:
        case CDISASM_CPU_TIGER_LAKE:
        case CDISASM_CPU_AMD_ZEN_4:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        case CDISASM_CPU_KNIGHTS_MILL:
            return vector_bits == 512u;
        default:
            return 0;
    }
}

static int cpu_has_avx512f_128n(cdisasm_x86_cpu_id cpu_id)
{
    /* AVX512F_128N is a foundation form that does not require AVX512VL.
     * Knights Mill therefore admits it even though ordinary 128-bit packed
     * AVX-512 forms are unavailable on that profile. */
    return cpu_id == CDISASM_CPU_KNIGHTS_MILL
        || cpu_has_avx512f_width(cpu_id, 128u);
}

static int cpu_has_avx512f_scalar(cdisasm_x86_cpu_id cpu_id)
{
    /* Exact pinned-XED AVX512F_SCALAR membership.  AVX10/APX expose this
     * promoted scalar foundation without publishing a legacy AVX512F bit. */
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_SKYLAKE_SP:
        case CDISASM_CPU_ICE_LAKE:
        case CDISASM_CPU_TIGER_LAKE:
        case CDISASM_CPU_AMD_ZEN_4:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_DIAMOND_RAPIDS:
        case CDISASM_CPU_KNIGHTS_MILL:
            return 1;
        default:
            return 0;
    }
}

static int cpu_has_avx512_fp16_scalar(cdisasm_x86_cpu_id cpu_id)
{
    /* The pinned ISA set has either an AVX512-FP16 route or the AVX10.1
     * promotion.  Keep structural profile admission available in an
     * extra-opcode-OFF build as well as in the semantic implementation. */
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        default:
            return 0;
    }
}

#if USE_EXTRA_OPCODES
static int cpu_has_avx512_fp16_128n(cdisasm_x86_cpu_id cpu_id)
{
    /* In the pinned catalog FP16_128N and FP16_SCALAR have the same exact
     * named-profile membership, but remain distinct public ISA-set bits. */
    return cpu_has_avx512_fp16_scalar(cpu_id);
}
#endif

static int cpu_has_avx512_movzxc_128(cdisasm_x86_cpu_id cpu_id)
{
    /* Pinned ISA_SET profile bit 169 is intentionally narrower than the
     * ordinary AVX512F 128-bit foundation sets. */
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_AVX10
        || cpu_id == CDISASM_CPU_APX
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}

#if USE_EXTRA_OPCODES
static int cpu_has_avx512_mediax_width(
    cdisasm_x86_cpu_id cpu_id,
    unsigned int vector_bits)
{
    /* Pinned XED publishes all three MEDIAX width sets on the unrestricted,
     * abstract AVX10/APX, and Diamond Rapids profiles only.  Keep the width
     * argument explicit so a future profile can expose a narrower set
     * without weakening the form-to-ISA_SET boundary. */
    if (vector_bits != 128u
        && vector_bits != 256u
        && vector_bits != 512u) {
        return 0;
    }
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_AVX10
        || cpu_id == CDISASM_CPU_APX
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}
#endif

static int cpu_has_avx10_movrs(cdisasm_x86_cpu_id cpu_id)
{
    /* The pinned AVX10_MOVRS width sets are currently published only by the
     * abstract AVX10/APX profiles and Diamond Rapids. */
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_AVX10
        || cpu_id == CDISASM_CPU_APX
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}

static int decode_vector_move_quadword_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0;
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0;
    const int is_66 = prefix == X86_SIMD_PREFIX_P66;
    const int is_f3 = prefix == X86_SIMD_PREFIX_PF3;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x6e)
            && opcode != UINT8_C(0x7e)
            && opcode != UINT8_C(0xd6))) {
        return -1;
    }

    /* The EVEX VMOVD/VMOVQ rows share their opcodes and address grammar.
     * Decode the complete effective address first so a missing SIB or
     * displacement wins over the eventual reserved/collision selector. */
    decoder->rex = 0;
    decoder->modrm_reg_high = 0;
    decoder->modrm_rm_high = 0;
    decoder->address_base_high = 0;
    decoder->address_index_high = 0;
    if (decoder->mode == CDISASM_MODE_64) {
        if ((p0 & UINT8_C(0x80)) == 0) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        if (apx_b4) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_x4) {
            decoder->address_index_high = 16u;
        }
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }

    /* For the two vector-register transfer spellings, EVEX.B4 qualifies
     * APX but does not extend XMM_B3.  X is its high vector-register bit.
     * The 66/6E and 66/7E register forms instead use B/B4 for the GPR. */
    if (modrm.is_register
        && (opcode == UINT8_C(0xd6)
            || (opcode == UINT8_C(0x7e) && is_f3))) {
        if (decoder->mode == CDISASM_MODE_64) {
            if (apx_b4) {
                modrm.rm = (uint8_t)(modrm.rm - 16u);
            }
            if ((p0 & UINT8_C(0x40)) == 0) {
                modrm.rm = (uint8_t)(modrm.rm + 16u);
            }
        }
    }

    if ((p1 & UINT8_C(0x78)) != UINT8_C(0x78)
        || (p2 & UINT8_C(0xf7)) != UINT8_C(0x00)
        || (p2 & UINT8_C(0x08)) == 0
        || (opcode == UINT8_C(0x6e) && !is_66)
        || (opcode == UINT8_C(0x7e) && !is_66 && !is_f3)
        || (opcode == UINT8_C(0xd6) && !is_66)
        || (apx_x4
            && (decoder->mode != CDISASM_MODE_64
                || modrm.is_register))
        || (apx_b4 && decoder->mode != CDISASM_MODE_64)
        || ((apx_b4 || apx_x4)
            && !cpu_has_apx_f(decoder->cpu_id))) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    /* W0 selects VMOVD (including MOVZXC's F3/7E and 66/D6 forms).
     * Non-long 66/6E and 66/7E ignore W and likewise remain VMOVD.  Gate
     * each collision by its exact generated ISA_SET before returning
     * UNSUPPORTED for fallback: the p66 forms use AVX512F_128N, whereas the
     * two vector-transfer spellings use the narrower AVX512_MOVZXC_128. */
    if (w == 0
        || ((opcode == UINT8_C(0x6e)
                || (opcode == UINT8_C(0x7e) && is_66))
            && decoder->mode != CDISASM_MODE_64)) {
        const int is_avx512f_128n_collision =
            opcode == UINT8_C(0x6e)
            || (opcode == UINT8_C(0x7e) && is_66);

        if (!(is_avx512f_128n_collision
                ? cpu_has_avx512f_128n(decoder->cpu_id)
                : cpu_has_avx512_movzxc_128(decoder->cpu_id))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    if (!cpu_has_avx512f_128n(decoder->cpu_id)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x6e)) {
        form_id = modrm.is_register
            ? UINT16_C(5894) : UINT16_C(5895);
    } else if (opcode == UINT8_C(0x7e) && is_66) {
        form_id = modrm.is_register
            ? UINT16_C(5885) : UINT16_C(5888);
    } else if (opcode == UINT8_C(0x7e)) {
        form_id = modrm.is_register
            ? UINT16_C(5896) : UINT16_C(5895);
    } else {
        form_id = modrm.is_register
            ? UINT16_C(5896) : UINT16_C(5888);
    }
    if (!modrm.is_register && modrm.mod == 1u) {
        modrm.displacement *= INT64_C(8);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_VMOVQ;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_evex_foundation(decoder, 0, 1);
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }

    if (opcode == UINT8_C(0x6e)) {
        if (!add_vector_register_operand_access(
                decoder, modrm.reg, 128u,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (modrm.is_register) {
            return add_register_operand_access(
                decoder, modrm.rm, 64u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, 64u, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    if (opcode == UINT8_C(0x7e) && is_66) {
        if (modrm.is_register) {
            if (!add_register_operand_access(
                    decoder, modrm.rm, 64u,
                    CDISASM_OPERAND_ACCESS_WRITE)) {
                return 0;
            }
        } else if (!add_rm_operand(decoder, &modrm, 64u, 1)
            || !set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        return add_vector_register_operand_access(
            decoder, modrm.reg, 128u,
            CDISASM_OPERAND_ACCESS_READ);
    }
    if (opcode == UINT8_C(0x7e)) {
        return add_vector_register_operand_access(
                   decoder, modrm.reg, 128u,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_rm_operand_access(
                   decoder, &modrm, 128u, 64u,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_rm_operand_access(
               decoder, &modrm, 128u, 64u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vector_move_word_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0;
    const int is_fp16 = prefix == X86_SIMD_PREFIX_P66;
    const int is_movzxc = prefix == X86_SIMD_PREFIX_PF3;
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(5)
        || (opcode != UINT8_C(0x6e)
            && opcode != UINT8_C(0x7e))) {
        return -1;
    }

    /* All map-5 6E/7E selectors belong to VMOVW.  Decode the complete
     * effective address before rejecting a reserved pp/W/U/control cell so
     * a missing SIB or displacement retains TRUNCATED precedence.  The p66
     * register forms use B/B4 for GPR32_B, while the F3 register forms use
     * X for XMM_B3 and treat B4 as an APX qualifier without extending it. */
    decoder->rex = 0;
    decoder->modrm_reg_high = 0;
    decoder->modrm_rm_high = 0;
    decoder->address_base_high = 0;
    decoder->address_index_high = 0;
    if (decoder->mode == CDISASM_MODE_64) {
        if ((p0 & UINT8_C(0x80)) == 0) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        if (apx_b4) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_x4) {
            decoder->address_index_high = 16u;
        }
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (is_movzxc && modrm.is_register
        && decoder->mode == CDISASM_MODE_64) {
        if (apx_b4) {
            modrm.rm = (uint8_t)(modrm.rm - 16u);
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            modrm.rm = (uint8_t)(modrm.rm + 16u);
        }
    }

    if ((!is_fp16 && !is_movzxc)
        || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)
        || (is_movzxc && w != 0u)
        || p2 != UINT8_C(0x08)
        || (apx_x4
            && (decoder->mode != CDISASM_MODE_64 || modrm.is_register))
        || (apx_b4 && decoder->mode != CDISASM_MODE_64)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (is_fp16) {
        if (opcode == UINT8_C(0x6e)) {
            form_id = modrm.is_register
                ? UINT16_C(5983) : UINT16_C(5984);
        } else {
            form_id = modrm.is_register
                ? UINT16_C(5980) : UINT16_C(5981);
        }
    } else if (modrm.is_register) {
        form_id = UINT16_C(5986);
    } else {
        form_id = opcode == UINT8_C(0x6e)
            ? UINT16_C(5985) : UINT16_C(5982);
    }
    if (!modrm.is_register && modrm.mod == 1u) {
        modrm.displacement *= INT64_C(2);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (((apx_b4 || apx_x4)
            && !cpu_has_apx_f(decoder->cpu_id))
        || !(is_fp16
            ? cpu_has_avx512_fp16_128n(decoder->cpu_id)
            : cpu_has_avx512_movzxc_128(decoder->cpu_id))) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->name_id = CDISASM_X86_NAME_VMOVW;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (is_fp16) {
        decoder_require_evex_fp16_foundation(decoder, 0);
    }
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }

    if (opcode == UINT8_C(0x6e)) {
        if (!add_vector_register_operand_access(
                decoder, modrm.reg, 128u,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (modrm.is_register) {
            return is_fp16
                ? add_register_operand_access(
                    decoder, modrm.rm, 32u,
                    CDISASM_OPERAND_ACCESS_READ)
                : add_vector_register_operand_access(
                    decoder, modrm.rm, 128u,
                    CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, 16u, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }

    if (modrm.is_register) {
        if (is_fp16) {
            if (!add_register_operand_access(
                    decoder, modrm.rm, 32u,
                    CDISASM_OPERAND_ACCESS_WRITE)) {
                return 0;
            }
        } else if (!add_vector_register_operand_access(
                decoder, modrm.rm, 128u,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
    } else if (!add_rm_operand(decoder, &modrm, 16u, 1)
        || !set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    return add_vector_register_operand_access(
        decoder, modrm.reg, 128u, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vector_move_read_shared_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode);

static int decode_unaligned_packed_move_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    static const cdisasm_x86_form_id pd_store_memory[3] = {
        UINT16_C(5947), UINT16_C(5948), UINT16_C(5949)
    };
    static const cdisasm_x86_form_id pd_load_memory[3] = {
        UINT16_C(5954), UINT16_C(5956), UINT16_C(5961)
    };
    static const cdisasm_x86_form_id pd_register[3] = {
        UINT16_C(5955), UINT16_C(5957), UINT16_C(5962)
    };
    static const cdisasm_x86_form_id ps_store_memory[3] = {
        UINT16_C(5964), UINT16_C(5965), UINT16_C(5966)
    };
    static const cdisasm_x86_form_id ps_load_memory[3] = {
        UINT16_C(5971), UINT16_C(5973), UINT16_C(5978)
    };
    static const cdisasm_x86_form_id ps_register[3] = {
        UINT16_C(5972), UINT16_C(5974), UINT16_C(5979)
    };
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const uint8_t aaa = p2 & UINT8_C(0x07);
    const unsigned int vector_bits = ll < 3u ? 128u << ll : 0u;
    const int is_pd = prefix == X86_SIMD_PREFIX_P66;
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0;
    const unsigned int encoded_source =
        (((unsigned int)(~p1) >> 3) & 15u)
        + ((p2 & UINT8_C(0x08)) == 0 ? 16u : 0u);
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x10) && opcode != UINT8_C(0x11))
        || (prefix != X86_SIMD_PREFIX_NONE
            && prefix != X86_SIMD_PREFIX_P66)) {
        return -1;
    }

    /* The NP/W0 and 66/W1 halves of 0F10/11 are VMOVUPS/VMOVUPD.  vvvv
     * and V' are fixed, b is reserved, and LL chooses one of three full
     * vector tuples.  Long-mode B4/X4 extend memory addresses; B4 remains
     * an ignored-but-APX qualifier for register rm.  Decode the complete
     * effective address before classifying controls so truncation wins. */
    decoder->rex = 0;
    decoder->modrm_reg_high = 0;
    decoder->modrm_rm_high = 0;
    decoder->address_base_high = 0;
    decoder->address_index_high = 0;
    if (decoder->mode == CDISASM_MODE_64) {
        if ((p0 & UINT8_C(0x80)) == 0) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        if (apx_b4) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_x4) {
            decoder->address_index_high = 16u;
        }
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register && decoder->mode == CDISASM_MODE_64) {
        if (apx_b4) {
            modrm.rm = (uint8_t)(modrm.rm - 16u);
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            modrm.rm = (uint8_t)(modrm.rm + 16u);
        }
    }

    if (w != (uint8_t)is_pd || ll == 3u
        || (p2 & UINT8_C(0x10)) != 0u
        || encoded_source != 0u
        || (apx_x4
            && (decoder->mode != CDISASM_MODE_64 || modrm.is_register))
        || (apx_b4 && decoder->mode != CDISASM_MODE_64)
        || ((p2 & UINT8_C(0x80)) != 0u
            && (aaa == 0u
                || (opcode == UINT8_C(0x11) && !modrm.is_register)))) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (modrm.is_register) {
        form_id = is_pd ? pd_register[ll] : ps_register[ll];
    } else if (opcode == UINT8_C(0x10)) {
        form_id = is_pd ? pd_load_memory[ll] : ps_load_memory[ll];
    } else {
        form_id = is_pd ? pd_store_memory[ll] : ps_store_memory[ll];
    }
    if (!modrm.is_register && modrm.mod == 1u) {
        modrm.displacement *= (int64_t)(vector_bits / 8u);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (((apx_b4 || apx_x4)
            && !cpu_has_apx_f(decoder->cpu_id))
        || !cpu_has_avx512f_width(decoder->cpu_id, vector_bits)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->name_id = is_pd
        ? CDISASM_X86_NAME_VMOVUPD : CDISASM_X86_NAME_VMOVUPS;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_evex_foundation(
        decoder, vector_bits < 512u, 1);
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (aaa != 0u) {
        decoder->mask_reg =
            (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = (p2 & UINT8_C(0x80)) != 0
            ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE;
    }
    if (opcode == UINT8_C(0x10)) {
        return add_vector_register_operand_access(
                   decoder, modrm.reg, vector_bits,
                   decoder->mask_mode == CDISASM_X86_MASK_MERGE
                       ? CDISASM_OPERAND_ACCESS_READ_WRITE
                       : CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_rm_operand_access(
                   decoder, &modrm, vector_bits, vector_bits,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               modrm.is_register
                       && decoder->mask_mode == CDISASM_X86_MASK_MERGE
                   ? CDISASM_OPERAND_ACCESS_READ_WRITE
                   : CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vector_duplicate_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const uint8_t aaa = p2 & UINT8_C(0x07);
    const unsigned int vector_bits = ll < 3u ? 128u << ll : 0u;
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0;
    const unsigned int encoded_source =
        (((unsigned int)(~p1) >> 3) & 15u)
        + ((p2 & UINT8_C(0x08)) == 0 ? 16u : 0u);
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x12) && opcode != UINT8_C(0x16))
        || prefix != X86_SIMD_PREFIX_PF3) {
        return -1;
    }

    /* These unary duplicate moves have W0, fixed vvvv/V', b=0 and three
     * real vector lengths.  B4/X4 retain the APX address interpretation;
     * for register sources B4 is ignored while ordinary EVEX.X selects the
     * high vector-register bank.  Complete ModRM addressing is consumed
     * before the control split to preserve TRUNCATED precedence. */
    decoder->rex = 0;
    decoder->modrm_reg_high = 0;
    decoder->modrm_rm_high = 0;
    decoder->address_base_high = 0;
    decoder->address_index_high = 0;
    if (decoder->mode == CDISASM_MODE_64) {
        if ((p0 & UINT8_C(0x80)) == 0) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        if (apx_b4) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_x4) {
            decoder->address_index_high = 16u;
        }
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register && decoder->mode == CDISASM_MODE_64) {
        if (apx_b4) {
            modrm.rm = (uint8_t)(modrm.rm - 16u);
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            modrm.rm = (uint8_t)(modrm.rm + 16u);
        }
    }

    if (w != 0u || ll == 3u || (p2 & UINT8_C(0x10)) != 0
        || encoded_source != 0u
        || (apx_x4
            && (decoder->mode != CDISASM_MODE_64 || modrm.is_register))
        || (apx_b4 && decoder->mode != CDISASM_MODE_64)
        || ((p2 & UINT8_C(0x80)) != 0 && aaa == 0u)
        || ((apx_b4 || apx_x4)
            && !cpu_has_apx_f(decoder->cpu_id))
        || !cpu_has_avx512f_width(decoder->cpu_id, vector_bits)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x16)) {
        static const cdisasm_x86_form_id memory_forms[3] = {
            UINT16_C(5918), UINT16_C(5920), UINT16_C(5924)
        };
        static const cdisasm_x86_form_id register_forms[3] = {
            UINT16_C(5919), UINT16_C(5921), UINT16_C(5925)
        };

        form_id = modrm.is_register
            ? register_forms[ll] : memory_forms[ll];
    } else {
        static const cdisasm_x86_form_id memory_forms[3] = {
            UINT16_C(5931), UINT16_C(5933), UINT16_C(5937)
        };
        static const cdisasm_x86_form_id register_forms[3] = {
            UINT16_C(5932), UINT16_C(5934), UINT16_C(5938)
        };

        form_id = modrm.is_register
            ? register_forms[ll] : memory_forms[ll];
    }
    if (!modrm.is_register && modrm.mod == 1u) {
        modrm.displacement *= (int64_t)(vector_bits / 8u);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = opcode == UINT8_C(0x16)
        ? CDISASM_X86_NAME_VMOVSHDUP
        : CDISASM_X86_NAME_VMOVSLDUP;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_evex_foundation(
        decoder, vector_bits < 512u, 1);
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (aaa != 0u) {
        decoder->mask_reg =
            (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = (p2 & UINT8_C(0x80)) != 0
            ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE;
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               decoder->mask_mode == CDISASM_X86_MASK_MERGE
                   ? CDISASM_OPERAND_ACCESS_READ_WRITE
                   : CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vector_move_scalar_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0;
    const int is_half = map_select == UINT8_C(5);
    const int is_double = !is_half && prefix == X86_SIMD_PREFIX_PF2;
    const unsigned int memory_bits = is_half
        ? 16u : is_double ? 64u : 32u;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const uint8_t aaa = p2 & UINT8_C(0x07);
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0;
    const unsigned int encoded_source =
        (((unsigned int)(~p1) >> 3) & 15u)
        + ((p2 & UINT8_C(0x08)) == 0 ? 16u : 0u);
    unsigned int source_index = encoded_source;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if ((map_select != UINT8_C(1) && map_select != UINT8_C(5))
        || (opcode != UINT8_C(0x10) && opcode != UINT8_C(0x11))
        || (!is_half && !is_double
            && prefix != X86_SIMD_PREFIX_PF3)) {
        return -1;
    }

    /* VMOVSD/VMOVSS/VMOVSH are scalar-LLIG (LL=0/1/2), respectively
     * W1/W0/W0, with b=0.  Decode the full address first so a missing
     * SIB/displacement wins over a reserved control.  In long mode B4/X4
     * extend addresses; B4 is ignored by a register rm operand but still
     * qualifies the encoding as APX. */
    decoder->rex = (uint8_t)(w ? UINT8_C(8) : UINT8_C(0));
    decoder->modrm_reg_high = 0;
    decoder->modrm_rm_high = 0;
    decoder->address_base_high = 0;
    decoder->address_index_high = 0;
    if (decoder->mode == CDISASM_MODE_64) {
        if ((p0 & UINT8_C(0x80)) == 0) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        if (apx_b4) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_x4) {
            decoder->address_index_high = 16u;
        }
    } else {
        /* B/R' and the encoded vvvv high bit are ignored outside long mode;
         * R/X are already fixed by 62/BOUND disambiguation. */
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register && decoder->mode == CDISASM_MODE_64) {
        if (apx_b4) {
            modrm.rm = (uint8_t)(modrm.rm - 16u);
        }
        if ((p0 & UINT8_C(0x40)) == 0) {
            modrm.rm = (uint8_t)(modrm.rm + 16u);
        }
    }

    if ((is_half && prefix != X86_SIMD_PREFIX_PF3)
        || w != (uint8_t)is_double
        || ll == 3u || (p2 & UINT8_C(0x10)) != 0
        || (apx_x4
            && (decoder->mode != CDISASM_MODE_64 || modrm.is_register))
        || (apx_b4 && decoder->mode != CDISASM_MODE_64)
        || (!modrm.is_register && encoded_source != 0u)
        || (modrm.is_register && decoder->mode != CDISASM_MODE_64
            && (p2 & UINT8_C(0x08)) == 0)
        || ((p2 & UINT8_C(0x80)) != 0
            && (aaa == 0u
                || (opcode == UINT8_C(0x11) && !modrm.is_register)))
        || ((apx_b4 || apx_x4)
            && !cpu_has_apx_f(decoder->cpu_id))
        || !(is_half
            ? cpu_has_avx512_fp16_scalar(decoder->cpu_id)
            : cpu_has_avx512f_scalar(decoder->cpu_id))) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (is_half) {
        form_id = modrm.is_register
            ? UINT16_C(5928)
            : (opcode == UINT8_C(0x10)
                ? UINT16_C(5927) : UINT16_C(5926));
    } else if (is_double) {
        form_id = modrm.is_register
            ? UINT16_C(5915)
            : (opcode == UINT8_C(0x10)
                ? UINT16_C(5914) : UINT16_C(5909));
    } else {
        form_id = modrm.is_register
            ? UINT16_C(5945)
            : (opcode == UINT8_C(0x10)
                ? UINT16_C(5944) : UINT16_C(5940));
    }
    if (!modrm.is_register && modrm.mod == 1u) {
        modrm.displacement *= (int64_t)(memory_bits / 8u);
    }

#if !USE_EXTRA_OPCODES
    (void)source_index;
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = is_half
        ? CDISASM_X86_NAME_VMOVSH
        : is_double ? CDISASM_X86_NAME_VMOVSD
                    : CDISASM_X86_NAME_VMOVSS;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (is_half) {
        decoder_require_evex_fp16_foundation(decoder, 0);
    }
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (aaa != 0u) {
        decoder->mask_reg =
            (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = (p2 & UINT8_C(0x80)) != 0
            ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE;
    }

    if (!modrm.is_register) {
        if (opcode == UINT8_C(0x10)) {
            return add_vector_register_operand_access(
                       decoder, modrm.reg, 128u,
                       decoder->mask_mode == CDISASM_X86_MASK_MERGE
                           ? CDISASM_OPERAND_ACCESS_READ_WRITE
                           : CDISASM_OPERAND_ACCESS_WRITE)
                && add_vector_rm_operand_access(
                       decoder, &modrm, 128u, memory_bits,
                       CDISASM_OPERAND_ACCESS_READ);
        }
        return add_vector_rm_operand_access(
                   decoder, &modrm, 128u, memory_bits,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                   decoder, modrm.reg, 128u,
                   CDISASM_OPERAND_ACCESS_READ);
    }

    if (opcode == UINT8_C(0x10)) {
        return add_vector_register_operand_access(
                   decoder, modrm.reg, 128u,
                   decoder->mask_mode == CDISASM_X86_MASK_MERGE
                       ? CDISASM_OPERAND_ACCESS_READ_WRITE
                       : CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                   decoder, source_index, 128u,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_vector_register_operand_access(
                   decoder, modrm.rm, 128u,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_register_operand_access(
               decoder, modrm.rm, 128u,
               decoder->mask_mode == CDISASM_X86_MASK_MERGE
                   ? CDISASM_OPERAND_ACCESS_READ_WRITE
                   : CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, source_index, 128u,
               CDISASM_OPERAND_ACCESS_READ)
        && add_vector_register_operand_access(
               decoder, modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vector_move_read_shared_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const uint8_t aaa = p2 & UINT8_C(0x07);
    const unsigned int vector_bits = ll < 3u ? 128u << ll : 0u;
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(5) || opcode != UINT8_C(0x6f)) {
        return -1;
    }

    /* This family is memory-only.  Decode the complete effective address
     * before rejecting reserved controls so truncation keeps precedence.
     * EVEX.B4 and raw U=0 are APX B4/X4 address extensions in long mode;
     * neither extends the vector destination. */
    decoder->rex = 0;
    decoder->modrm_reg_high = 0;
    decoder->modrm_rm_high = 0;
    decoder->address_base_high = 0;
    decoder->address_index_high = 0;
    if ((p0 & UINT8_C(0x80)) == 0) {
        decoder->rex |= UINT8_C(4);
    }
    if ((p0 & UINT8_C(0x40)) == 0) {
        decoder->rex |= UINT8_C(2);
    }
    if ((p0 & UINT8_C(0x20)) == 0) {
        decoder->rex |= UINT8_C(1);
    }
    decoder->modrm_reg_high =
        (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    if (apx_b4) {
        decoder->modrm_rm_high = 16u;
        decoder->address_base_high = 16u;
    }
    if (apx_x4) {
        decoder->address_index_high = 16u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }

    if (decoder->mode != CDISASM_MODE_64 || modrm.is_register || ll == 3u
        || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)
        || (p2 & UINT8_C(0x18)) != UINT8_C(0x08)
        || (prefix != X86_SIMD_PREFIX_PF2
            && prefix != X86_SIMD_PREFIX_PF3)
        || ((p2 & UINT8_C(0x80)) != 0 && aaa == 0)
        || ((apx_b4 || apx_x4)
            && !cpu_has_apx_f(decoder->cpu_id))
        || !cpu_has_avx10_movrs(decoder->cpu_id)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (prefix == X86_SIMD_PREFIX_PF2) {
        name_id = w == 0
            ? CDISASM_X86_NAME_VMOVRSB
            : CDISASM_X86_NAME_VMOVRSW;
        form_id = (cdisasm_x86_form_id)(
            (w == 0 ? UINT16_C(5897) : UINT16_C(5906)) + ll);
    } else {
        name_id = w == 0
            ? CDISASM_X86_NAME_VMOVRSD
            : CDISASM_X86_NAME_VMOVRSQ;
        form_id = (cdisasm_x86_form_id)(
            (w == 0 ? UINT16_C(5900) : UINT16_C(5903)) + ll);
    }
    if (modrm.mod == 1u) {
        modrm.displacement *= (int64_t)(vector_bits / 8u);
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_extra(
        decoder,
        (cdisasm_x86_group_id)(
            CDISASM_X86_GROUP_AVX10_MOVRS_128 + ll));
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (aaa != 0) {
        decoder->mask_reg =
            (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = (p2 & UINT8_C(0x80)) != 0
            ? CDISASM_X86_MASK_ZERO
            : CDISASM_X86_MASK_MERGE;
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               decoder->mask_mode == CDISASM_X86_MASK_MERGE
                   ? CDISASM_OPERAND_ACCESS_READ_WRITE
                   : CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_non_temporal_aligned_load_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const unsigned int vector_bits = ll < 3u ? 128u << ll : 0u;
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    /* F3/W1/register at this opcode is VPBROADCASTMB2Q.  Leave every
     * non-66 selector to the existing EVEX collision machinery. */
    if (map_select != UINT8_C(2) || opcode != UINT8_C(0x2a)
        || prefix != X86_SIMD_PREFIX_P66) {
        return -1;
    }

    /* Decode the full memory address before validating W, vvvv, V', masking,
     * or length.  B4 and raw U=0 carry APX B4/X4 address extensions for this
     * memory-only row; neither extends the vector destination. */
    decoder->rex = 0;
    if ((p0 & UINT8_C(0x80)) == 0) {
        decoder->rex |= UINT8_C(4);
    }
    if ((p0 & UINT8_C(0x40)) == 0) {
        decoder->rex |= UINT8_C(2);
    }
    if ((p0 & UINT8_C(0x20)) == 0) {
        decoder->rex |= UINT8_C(1);
    }
    decoder->rex_present = 0;
    decoder->modrm_reg_high =
        (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    if (apx_b4) {
        decoder->modrm_rm_high = 16u;
        decoder->address_base_high = 16u;
    }
    if (apx_x4) {
        decoder->address_index_high = 16u;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }

    if (modrm.is_register || w != 0 || ll == 3u
        || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)
        || (p2 & UINT8_C(0x9f)) != UINT8_C(0x08)
        || (decoder->mode != CDISASM_MODE_64
            && ((p0 & UINT8_C(0xf8)) != UINT8_C(0xf0)
                || modrm.reg >= 8
                || (modrm.base >= 8 && modrm.base >= 0)
                || (modrm.index >= 8 && modrm.index >= 0)))
        || ((apx_b4 || apx_x4)
            && (decoder->mode != CDISASM_MODE_64
                || !cpu_has_apx_f(decoder->cpu_id)))) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!cpu_has_avx512f_width(decoder->cpu_id, vector_bits)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    form_id = ll == 0u
        ? UINT16_C(5865)
        : (cdisasm_x86_form_id)(UINT16_C(5866) + ll);
    if (modrm.mod == 1u) {
        modrm.displacement *= (int64_t)(vector_bits / 8u);
    }

#if !USE_EXTRA_OPCODES
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_VMOVNTDQA;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_non_temporal_vector_store_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const unsigned int vector_bits = ll < 3u ? 128u << ll : 0u;
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    if (map_select != UINT8_C(1)
        || (opcode != UINT8_C(0x2b) && opcode != UINT8_C(0xe7))) {
        return -1;
    }

    /* Decode ModRM with the EVEX R/R'/X/B fields and APX B4/X4 address bits
     * before applying reserved-control policy.  Raw U=0 supplies inverted
     * X4 for these memory-only rows; it is not a vector-register control. */
    decoder->rex = 0;
    if ((p0 & UINT8_C(0x80)) == 0) {
        decoder->rex |= UINT8_C(4);
    }
    if ((p0 & UINT8_C(0x40)) == 0) {
        decoder->rex |= UINT8_C(2);
    }
    if ((p0 & UINT8_C(0x20)) == 0) {
        decoder->rex |= UINT8_C(1);
    }
    decoder->rex_present = 0;
    decoder->modrm_reg_high =
        (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    if (apx_b4) {
        decoder->modrm_rm_high = 16u;
        decoder->address_base_high = 16u;
    }
    if (apx_x4) {
        decoder->address_index_high = 16u;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }

    if (modrm.is_register || ll == 3u
        || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)
        || (p2 & UINT8_C(0x9f)) != UINT8_C(0x08)
        || (opcode == UINT8_C(0xe7)
            && (prefix != X86_SIMD_PREFIX_P66 || w != 0))
        || (opcode == UINT8_C(0x2b)
            && !((prefix == X86_SIMD_PREFIX_NONE && w == 0)
                || (prefix == X86_SIMD_PREFIX_P66 && w != 0)))
        || (decoder->mode != CDISASM_MODE_64
            && ((p0 & UINT8_C(0xf8)) != UINT8_C(0xf0)
                || modrm.reg >= 8
                || (modrm.base >= 8 && modrm.base >= 0)
                || (modrm.index >= 8 && modrm.index >= 0)))
        || ((apx_b4 || apx_x4)
            && (decoder->mode != CDISASM_MODE_64
                || !cpu_has_apx_f(decoder->cpu_id)))) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!cpu_has_avx512f_width(decoder->cpu_id, vector_bits)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0xe7)) {
        name_id = CDISASM_X86_NAME_VMOVNTDQ;
        form_id = (cdisasm_x86_form_id)(UINT16_C(5871) + ll);
    } else if (prefix == X86_SIMD_PREFIX_P66) {
        name_id = CDISASM_X86_NAME_VMOVNTPD;
        form_id = (cdisasm_x86_form_id)(UINT16_C(5875) + ll);
    } else {
        name_id = CDISASM_X86_NAME_VMOVNTPS;
        form_id = (cdisasm_x86_form_id)(UINT16_C(5880) + ll);
    }
    if (modrm.mod == 1u) {
        modrm.displacement *= (int64_t)(vector_bits / 8u);
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    return add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_vdbpsadbw_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0u;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const uint8_t aaa = p2 & UINT8_C(0x07);
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0u;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0u;
    unsigned int source_index =
        (((unsigned int)(~p1) >> 3) & 15u)
        + ((p2 & UINT8_C(0x08)) == 0u ? 16u : 0u);
    const unsigned int vector_bits = ll < 3u ? 128u << ll : 0u;
    uint64_t immediate;
    x86_modrm modrm;

    if (map_select != UINT8_C(3) || opcode != UINT8_C(0x42)
        || prefix != X86_SIMD_PREFIX_P66) {
        return -1;
    }

    /* VDBPSADBW owns the complete EVEX.66.0F3A 42 selector.  Decode the
     * shared ModRM/address/imm8 payload before rejecting reserved controls
     * so truncation always has architectural precedence. */
    decoder->rex = 0;
    decoder->modrm_reg_high = 0;
    decoder->modrm_rm_high = 0;
    decoder->address_base_high = 0;
    decoder->address_index_high = 0;
    if (decoder->mode == CDISASM_MODE_64) {
        if ((p0 & UINT8_C(0x80)) == 0u) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0u) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0u ? 16u : 0u;
        if (apx_b4) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_x4) {
            decoder->address_index_high = 16u;
        }
    } else {
        /* R'/B/vvvv[3] are ignored outside long mode; V' remains fixed. */
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register && decoder->mode == CDISASM_MODE_64) {
        if (apx_b4) {
            modrm.rm = (uint8_t)(modrm.rm - 16u);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            modrm.rm = (uint8_t)(modrm.rm + 16u);
        }
    }
    if (!read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }

    if (decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u
        || w != 0u || ll == 3u
        || (p2 & UINT8_C(0x10)) != 0u
        || ((p2 & UINT8_C(0x80)) != 0u && aaa == 0u)
        || (apx_x4
            && (decoder->mode != CDISASM_MODE_64
                || modrm.is_register))
        || (apx_b4 && decoder->mode != CDISASM_MODE_64)
        || (decoder->mode != CDISASM_MODE_64
            && (p2 & UINT8_C(0x08)) == 0u)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!modrm.is_register && modrm.mod == 1u) {
        /* DISP8_FULLMEM: EVEX.b is reserved, so every memory form uses the
         * complete 16/32/64-byte tuple selected by LL. */
        modrm.displacement *= (int64_t)(vector_bits / 8u);
    }

#if !USE_EXTRA_OPCODES
    (void)immediate;
    (void)source_index;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if ((apx_b4 || apx_x4)
        && !cpu_has_apx_f(decoder->cpu_id)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->name_id = CDISASM_X86_NAME_VDBPSADBW;
    decoder->form_id = (cdisasm_x86_form_id)(
        UINT16_C(4453) + 2u * ll + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_evex_packed_integer_foundation(
        decoder, CDISASM_X86_GROUP_AVX512BW, vector_bits < 512u);
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (aaa != 0u) {
        decoder->mask_reg =
            (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = (p2 & UINT8_C(0x80)) != 0u
            ? CDISASM_X86_MASK_ZERO
            : CDISASM_X86_MASK_MERGE;
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               decoder->mask_mode == CDISASM_X86_MASK_MERGE
                   ? CDISASM_OPERAND_ACCESS_READ_WRITE
                   : CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, source_index, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

/* Decode the complete EVEX.66/F3.0F38 26/27 vector-test-to-mask rows. */
static int decode_vptest_mask_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    static const cdisasm_x86_name_id names[2][2][2] = {
        {
            {CDISASM_X86_NAME_VPTESTMB, CDISASM_X86_NAME_VPTESTMW},
            {CDISASM_X86_NAME_VPTESTMD, CDISASM_X86_NAME_VPTESTMQ}
        },
        {
            {CDISASM_X86_NAME_VPTESTNMB, CDISASM_X86_NAME_VPTESTNMW},
            {CDISASM_X86_NAME_VPTESTNMD, CDISASM_X86_NAME_VPTESTNMQ}
        }
    };
    static const cdisasm_x86_form_id form_bases[2][2][2] = {
        {
            {UINT16_C(8271), UINT16_C(8289)},
            {UINT16_C(8277), UINT16_C(8283)}
        },
        {
            {UINT16_C(8295), UINT16_C(8313)},
            {UINT16_C(8301), UINT16_C(8307)}
        }
    };
    const uint8_t prefix = p1 & UINT8_C(3);
    const uint8_t w = (p1 >> 7) & UINT8_C(1);
    const uint8_t ll = (p2 >> 5) & UINT8_C(3);
    const uint8_t aaa = p2 & UINT8_C(7);
    const int negative = prefix == X86_SIMD_PREFIX_PF3;
    const int dword_row = opcode == UINT8_C(0x27);
    const int broadcast = (p2 & UINT8_C(0x10)) != 0u;
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0u;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0u;
    unsigned int source_index =
        (((unsigned int)(~p1) >> 3) & 15u)
        + ((p2 & UINT8_C(0x08)) == 0u ? 16u : 0u);
    const unsigned int vector_bits = ll < 3u ? 128u << ll : 0u;
    const unsigned int element_bits = dword_row
        ? (w != 0u ? 64u : 32u) : (w != 0u ? 16u : 8u);
    x86_modrm modrm;

    if (map_select != UINT8_C(2)
        || (opcode != UINT8_C(0x26) && opcode != UINT8_C(0x27))
        || (prefix != X86_SIMD_PREFIX_P66
            && prefix != X86_SIMD_PREFIX_PF3)) {
        return -1;
    }

    decoder->rex = 0u;
    decoder->modrm_reg_high = 0u;
    decoder->modrm_rm_high = 0u;
    decoder->address_base_high = 0u;
    decoder->address_index_high = 0u;
    if (decoder->mode == CDISASM_MODE_64) {
        if ((p0 & UINT8_C(0x80)) == 0u) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0u) {
            decoder->rex |= UINT8_C(1);
        }
        if (apx_b4) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_x4) {
            decoder->address_index_high = 16u;
        }
    } else {
        source_index &= 7u;
    }
    decoder->rex_present = 0u;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register && decoder->mode == CDISASM_MODE_64) {
        if (apx_b4) {
            modrm.rm = (uint8_t)(modrm.rm - 16u);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            modrm.rm = (uint8_t)(modrm.rm + 16u);
        }
    }

    if (decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u
        || ll == 3u || (p2 & UINT8_C(0x80)) != 0u
        || (broadcast && (modrm.is_register || !dword_row))
        || (apx_x4
            && (decoder->mode != CDISASM_MODE_64 || modrm.is_register))
        || (apx_b4 && decoder->mode != CDISASM_MODE_64)
        || (decoder->mode != CDISASM_MODE_64
            && (p2 & UINT8_C(0x08)) == 0u)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!modrm.is_register && modrm.mod == 1u) {
        const unsigned int tuple_bits = broadcast
            ? element_bits : vector_bits;

        modrm.displacement *= (int64_t)(tuple_bits / 8u);
    }

#if !USE_EXTRA_OPCODES
    (void)names;
    (void)form_bases;
    (void)negative;
    (void)aaa;
    (void)source_index;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if ((apx_b4 || apx_x4) && !cpu_has_apx_f(decoder->cpu_id)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->name_id = names[negative][dword_row][w];
    decoder->form_id = (cdisasm_x86_form_id)(
        form_bases[negative][dword_row][w]
        + 2u * ll + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_evex_packed_integer_foundation(
        decoder,
        dword_row ? CDISASM_X86_GROUP_AVX512F
                  : CDISASM_X86_GROUP_AVX512BW,
        vector_bits < 512u);
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (aaa != 0u) {
        decoder->mask_reg =
            (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = CDISASM_X86_MASK_MERGE;
    }
    if (!add_mask_register_operand_access(
            decoder, modrm.reg3, vector_bits / element_bits,
            aaa != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                      : CDISASM_OPERAND_ACCESS_WRITE)
        || !add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        || !add_vector_rm_operand_access(
            decoder, &modrm, vector_bits,
            !modrm.is_register && broadcast ? element_bits : vector_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (!modrm.is_register && broadcast) {
        decoder->operand[decoder->operand_count - 1u].broadcast =
            (cdisasm_x86_broadcast)(vector_bits / element_bits);
    }
    return 1;
#endif
}

/* Decode the complete EVEX.66.0F3A 25 ternary-logic row.  VPTERNLOG's
 * destination is also its first boolean input, so its access remains RW even
 * for an unmasked or zero-masked encoding. */
static int decode_vpternlog_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0u;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const uint8_t aaa = p2 & UINT8_C(0x07);
    const int broadcast = (p2 & UINT8_C(0x10)) != 0u;
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0u;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0u;
    unsigned int source_index =
        (((unsigned int)(~p1) >> 3) & 15u)
        + ((p2 & UINT8_C(0x08)) == 0u ? 16u : 0u);
    const unsigned int vector_bits = ll < 3u ? 128u << ll : 0u;
    const unsigned int element_bits = w != 0u ? 64u : 32u;
    uint64_t immediate;
    x86_modrm modrm;

    if (map_select != UINT8_C(3) || opcode != UINT8_C(0x25)) {
        return -1;
    }

    /* Every pp/W/LL/mask cell in this owned opcode row has the same
     * ModRM/address/imm8 payload.  Consume all of it before applying exact
     * selector legality so truncated encodings keep precedence. */
    decoder->rex = (uint8_t)(w != 0u ? 8u : 0u);
    decoder->modrm_reg_high = 0u;
    decoder->modrm_rm_high = 0u;
    decoder->address_base_high = 0u;
    decoder->address_index_high = 0u;
    if (decoder->mode == CDISASM_MODE_64) {
        if ((p0 & UINT8_C(0x80)) == 0u) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0u) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0u ? 16u : 0u;
        if (apx_b4) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_x4) {
            decoder->address_index_high = 16u;
        }
    } else {
        /* Pinned XED aliases R'/B/vvvv[3] outside long mode.  The BOUND
         * discriminator already fixes R/X, while V' remains required. */
        source_index &= 7u;
    }
    decoder->rex_present = 0u;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register && decoder->mode == CDISASM_MODE_64) {
        /* APX B4 qualifies but does not extend a vector r/m operand.  The
         * ordinary EVEX.X field supplies that register's high bank. */
        if (apx_b4) {
            modrm.rm = (uint8_t)(modrm.rm - 16u);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            modrm.rm = (uint8_t)(modrm.rm + 16u);
        }
    }
    if (!read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }

    if (decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u
        || prefix != X86_SIMD_PREFIX_P66 || ll == 3u
        || (broadcast && modrm.is_register)
        || ((p2 & UINT8_C(0x80)) != 0u && aaa == 0u)
        || (apx_x4
            && (decoder->mode != CDISASM_MODE_64
                || modrm.is_register))
        || (apx_b4 && decoder->mode != CDISASM_MODE_64)
        || (decoder->mode != CDISASM_MODE_64
            && (p2 & UINT8_C(0x08)) == 0u)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!modrm.is_register && modrm.mod == 1u) {
        const unsigned int tuple_bits = broadcast
            ? element_bits : vector_bits;

        modrm.displacement *= (int64_t)(tuple_bits / 8u);
    }

#if !USE_EXTRA_OPCODES
    (void)immediate;
    (void)source_index;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (((apx_b4 || apx_x4)
            && !cpu_has_apx_f(decoder->cpu_id))
        || !cpu_has_avx512f_width(decoder->cpu_id, vector_bits)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->name_id = w != 0u
        ? CDISASM_X86_NAME_VPTERNLOGQ
        : CDISASM_X86_NAME_VPTERNLOGD;
    decoder->form_id = (cdisasm_x86_form_id)(
        (w != 0u ? UINT16_C(8265) : UINT16_C(8259))
        + 2u * ll + (modrm.is_register ? 1u : 0u));
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_evex_foundation(
        decoder, vector_bits < 512u, 1);
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (aaa != 0u) {
        decoder->mask_reg =
            (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = (p2 & UINT8_C(0x80)) != 0u
            ? CDISASM_X86_MASK_ZERO
            : CDISASM_X86_MASK_MERGE;
    }
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        || !add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        || !add_vector_rm_operand_access(
            decoder, &modrm, vector_bits,
            !modrm.is_register && broadcast ? element_bits : vector_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (!modrm.is_register && broadcast) {
        decoder->operand[decoder->operand_count - 1u].broadcast =
            (cdisasm_x86_broadcast)(vector_bits / element_bits);
    }
    return add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_vmpsadbw_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    static const cdisasm_x86_form_id memory_forms[3] = {
        UINT16_C(5989), UINT16_C(5993), UINT16_C(5995)
    };
    static const cdisasm_x86_form_id register_forms[3] = {
        UINT16_C(5990), UINT16_C(5994), UINT16_C(5996)
    };
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0u;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const uint8_t aaa = p2 & UINT8_C(0x07);
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0u;
    const int apx_x4 = (p1 & UINT8_C(0x04)) == 0u;
    unsigned int source_index =
        (((unsigned int)(~p1) >> 3) & 15u)
        + ((p2 & UINT8_C(0x08)) == 0u ? 16u : 0u);
    unsigned int vector_bits = ll < 3u ? 128u << ll : 0u;
    uint64_t immediate;
    cdisasm_x86_form_id form_id;
    x86_modrm modrm;

    /* VDBPSADBW owns prefix 66 above.  VMPSADBW owns the other prefix
     * selectors: F3 is allocated while none/F2 are reserved after their
     * shared ModRM/address/immediate payload. */
    if (map_select != UINT8_C(3) || opcode != UINT8_C(0x42)
        || prefix == X86_SIMD_PREFIX_P66) {
        return -1;
    }

    decoder->rex = 0;
    decoder->modrm_reg_high = 0;
    decoder->modrm_rm_high = 0;
    decoder->address_base_high = 0;
    decoder->address_index_high = 0;
    if (decoder->mode == CDISASM_MODE_64) {
        if ((p0 & UINT8_C(0x80)) == 0u) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0u) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0u ? 16u : 0u;
        if (apx_b4) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_x4) {
            decoder->address_index_high = 16u;
        }
    } else {
        /* R'/B/vvvv[3] are ignored outside long mode; V' remains fixed. */
        source_index &= 7u;
    }
    decoder->rex_present = 0;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register && decoder->mode == CDISASM_MODE_64) {
        if (apx_b4) {
            modrm.rm = (uint8_t)(modrm.rm - 16u);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            modrm.rm = (uint8_t)(modrm.rm + 16u);
        }
    }
    /* Every selector in this owned F3 row carries imm8. */
    if (!read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }

    if (decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u
        || prefix != X86_SIMD_PREFIX_PF3
        || w != 0u || ll == 3u
        || (p2 & UINT8_C(0x10)) != 0u
        || ((p2 & UINT8_C(0x80)) != 0u && aaa == 0u)
        || (apx_x4
            && (decoder->mode != CDISASM_MODE_64
                || modrm.is_register))
        || (apx_b4 && decoder->mode != CDISASM_MODE_64)
        || (decoder->mode != CDISASM_MODE_64
            && (p2 & UINT8_C(0x08)) == 0u)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!modrm.is_register && modrm.mod == 1u) {
        modrm.displacement *= (int64_t)(vector_bits / 8u);
    }
    form_id = modrm.is_register
        ? register_forms[ll] : memory_forms[ll];

#if !USE_EXTRA_OPCODES
    (void)form_id;
    (void)immediate;
    (void)source_index;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (((apx_b4 || apx_x4)
            && !cpu_has_apx_f(decoder->cpu_id))
        || !cpu_has_avx512_mediax_width(
            decoder->cpu_id, vector_bits)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->name_id = CDISASM_X86_NAME_VMPSADBW;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AVX);
    if (apx_b4 || apx_x4) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (aaa != 0u) {
        decoder->mask_reg =
            (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = (p2 & UINT8_C(0x80)) != 0u
            ? CDISASM_X86_MASK_ZERO
            : CDISASM_X86_MASK_MERGE;
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, vector_bits,
               decoder->mask_mode == CDISASM_X86_MASK_MERGE
                   ? CDISASM_OPERAND_ACCESS_READ_WRITE
                   : CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_register_operand_access(
               decoder, source_index, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_vector_rm_operand_access(
               decoder, &modrm, vector_bits, vector_bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int gfni_evex_opcode_owned(uint8_t map_select, uint8_t opcode)
{
    return (map_select == UINT8_C(3)
            && (opcode == UINT8_C(0xce) || opcode == UINT8_C(0xcf)))
        || (map_select == UINT8_C(2) && opcode == UINT8_C(0xcf));
}

static int compress_expand_evex_opcode_owned(
    uint8_t map_select,
    uint8_t opcode)
{
    return map_select == UINT8_C(2)
        && (opcode == UINT8_C(0x62) || opcode == UINT8_C(0x63)
            || opcode == UINT8_C(0x88) || opcode == UINT8_C(0x89)
            || opcode == UINT8_C(0x8a) || opcode == UINT8_C(0x8b));
}

/* Decode the complete EVEX GFNI allocation.  GFNI remains an independent
 * prerequisite on both the AVX-512 and AVX10.1 routes; it must never be
 * absorbed into the generic packed-integer foundation helper. */
static int decode_gfni_evex(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t map_select,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(0x03);
    const uint8_t w = (p1 & UINT8_C(0x80)) != 0u;
    const uint8_t ll = (p2 >> 5) & UINT8_C(0x03);
    const uint8_t aaa = p2 & UINT8_C(0x07);
    const int affine = map_select == UINT8_C(3);
    const int apx_b4 = (p0 & UINT8_C(0x08)) != 0u;
    const int apx_u0 = (p1 & UINT8_C(0x04)) == 0u;
    unsigned int source_index = ((unsigned int)(~p1) >> 3) & 15u;
    unsigned int vector_bits;
    unsigned int broadcast_count;
    x86_modrm modrm;
    uint64_t immediate = 0u;

    if (!gfni_evex_opcode_owned(map_select, opcode)) {
        return -1;
    }
    source_index += (p2 & UINT8_C(0x08)) == 0u ? 16u : 0u;

    decoder->rex = (uint8_t)(w ? 8u : 0u);
    if ((p0 & UINT8_C(0x80)) == 0u) {
        decoder->rex |= UINT8_C(4);
    }
    if ((p0 & UINT8_C(0x40)) == 0u) {
        decoder->rex |= UINT8_C(2);
    }
    if ((p0 & UINT8_C(0x20)) == 0u) {
        decoder->rex |= UINT8_C(1);
    }
    decoder->rex_present = 0;
    decoder->modrm_reg_high =
        (p0 & UINT8_C(0x10)) == 0u ? 16u : 0u;
    if (decoder->mode != CDISASM_MODE_64) {
        /* Once 62 has passed the non-long BOUND discriminator, pinned XED
         * treats B', R4, and the high VEX.vvvv bit as aliases. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        decoder->modrm_reg_high = 0u;
        source_index &= 7u;
    }
    if (apx_b4) {
        decoder->modrm_rm_high = 16u;
        decoder->address_base_high = 16u;
    }
    if (apx_u0) {
        /* APX reinterprets U=0 as inverted X4 for memory addressing. */
        decoder->address_index_high = 16u;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register && apx_b4) {
        /* B4 qualifies the encoding but does not extend a vector register. */
        modrm.rm = (uint8_t)(modrm.rm - 16u);
    }
    if (modrm.is_register && (p0 & UINT8_C(0x40)) == 0u) {
        modrm.rm = (uint8_t)(modrm.rm + 16u);
    }
    if (affine && !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }

    /* Exact selectors are pp=66 and W1 for affine/W0 for multiply.  U=0 is
     * APX X4 and is allocated only for long-mode memory.  Register EVEX.b
     * is always reserved; only affine memory permits m64 broadcast. */
    if (prefix != X86_SIMD_PREFIX_P66
        || w != (uint8_t)affine
        || ll == UINT8_C(3)
        || ((p2 & UINT8_C(0x80)) != 0u && aaa == 0u)
        || ((p2 & UINT8_C(0x10)) != 0u
            && (modrm.is_register || !affine))
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u
        || (apx_u0
            && (decoder->mode != CDISASM_MODE_64 || modrm.is_register))
        || (decoder->mode != CDISASM_MODE_64
            && (apx_b4 || apx_u0
                || (p0 & UINT8_C(0xc0)) != UINT8_C(0xc0)
                || (p2 & UINT8_C(0x08)) == 0u))
        || ((apx_b4 || apx_u0)
            && !cpu_has_apx_f(decoder->cpu_id))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    vector_bits = 128u << ll;
    if (!modrm.is_register && modrm.mod == 1) {
        const unsigned int tuple_bits =
            (p2 & UINT8_C(0x10)) != 0u ? 64u : vector_bits;

        modrm.displacement *= (int64_t)(tuple_bits / 8u);
    }
    broadcast_count = vector_bits / 64u;

#if !USE_EXTRA_OPCODES
    (void)broadcast_count;
    (void)immediate;
    (void)source_index;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    {
        cdisasm_x86_form_id base;

        if (affine) {
            const int inverse = opcode == UINT8_C(0xcf);

            base = inverse ? UINT16_C(5505) : UINT16_C(5515);
            base = (cdisasm_x86_form_id)(base + 4u * ll);
            decoder->name_id = inverse
                ? CDISASM_X86_NAME_VGF2P8AFFINEINVQB
                : CDISASM_X86_NAME_VGF2P8AFFINEQB;
        } else {
            base = (cdisasm_x86_form_id)(UINT16_C(5525) + 4u * ll);
            decoder->name_id = CDISASM_X86_NAME_VGF2P8MULB;
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            base + (modrm.is_register ? 1u : 0u));
    }
    decoder_require_caps(decoder, X86_CAP_AVX);
    decoder_require_evex_foundation(decoder, vector_bits < 512u, 1);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_GFNI);
    if (apx_b4 || apx_u0) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (aaa != 0u) {
        decoder->mask_reg =
            (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = (p2 & UINT8_C(0x80)) != 0u
            ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE;
    }
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, vector_bits,
            decoder->mask_mode == CDISASM_X86_MASK_MERGE
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        || !add_vector_register_operand_access(
            decoder, source_index, vector_bits,
            CDISASM_OPERAND_ACCESS_READ)
        || !add_vector_rm_operand_access(
            decoder, &modrm, vector_bits,
            !modrm.is_register && (p2 & UINT8_C(0x10)) != 0u
                ? 64u : vector_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (!modrm.is_register && (p2 & UINT8_C(0x10)) != 0u) {
        decoder->operand[decoder->operand_count - 1u].broadcast =
            (cdisasm_x86_broadcast)broadcast_count;
    }
    return !affine
        || add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_evex_apx_kmov(
    x86_decoder *decoder, uint8_t p0, uint8_t p1, uint8_t p2,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(3);
    const uint8_t w = (p1 >> 7) & UINT8_C(1);
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id group_id;
    cdisasm_x86_form_id form_id;
    unsigned int bits;
    x86_modrm modrm;

    if (decoder->mode != CDISASM_MODE_64
        || p2 != UINT8_C(0x08)
        || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (prefix == X86_SIMD_PREFIX_P66) {
        name_id = w != 0 ? CDISASM_X86_NAME_KMOVD : CDISASM_X86_NAME_KMOVB;
        group_id = w != 0 ? CDISASM_X86_GROUP_APX_F_KOPD
                          : CDISASM_X86_GROUP_APX_F_KOPB;
        bits = w != 0 ? 32u : 8u;
        form_id = w != 0 ? UINT16_C(1510) : UINT16_C(1500);
    } else if (prefix == X86_SIMD_PREFIX_NONE) {
        name_id = w != 0 ? CDISASM_X86_NAME_KMOVQ : CDISASM_X86_NAME_KMOVW;
        group_id = w != 0 ? CDISASM_X86_GROUP_APX_F_KOPQ
                          : CDISASM_X86_GROUP_APX_F_KOPW;
        bits = w != 0 ? 64u : 16u;
        form_id = w != 0 ? UINT16_C(1520) : UINT16_C(1530);
    } else if (prefix == X86_SIMD_PREFIX_PF2
               && (opcode == UINT8_C(0x92)
                   || opcode == UINT8_C(0x93))) {
        name_id = w != 0 ? CDISASM_X86_NAME_KMOVQ : CDISASM_X86_NAME_KMOVD;
        group_id = w != 0 ? CDISASM_X86_GROUP_APX_F_KOPQ
                          : CDISASM_X86_GROUP_APX_F_KOPD;
        bits = w != 0 ? 64u : 32u;
        form_id = w != 0 ? UINT16_C(1518) : UINT16_C(1508);
    } else {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->rex = (uint8_t)(w != 0 ? 8u : 0u);
    if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
    if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
    if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
    decoder->rex_present = 0;
    decoder->modrm_reg_high = (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    decoder->modrm_rm_high = (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
    decoder->address_base_high = decoder->modrm_rm_high;
    if ((p1 & UINT8_C(0x04)) == 0) decoder->address_index_high = 16u;
    if (!decode_modrm(decoder, &modrm)) return 0;

    if ((opcode != UINT8_C(0x90) && opcode != UINT8_C(0x91)
            && opcode != UINT8_C(0x92) && opcode != UINT8_C(0x93))
        || (opcode == UINT8_C(0x91) && modrm.is_register)
        || ((opcode == UINT8_C(0x92) || opcode == UINT8_C(0x93))
            && !modrm.is_register)
        || (modrm.is_register && (p1 & UINT8_C(0x04)) == 0)
        || (opcode != UINT8_C(0x93) && modrm.reg >= 8u)
        || (opcode == UINT8_C(0x93) && modrm.rm >= 8u)
        || ((opcode == UINT8_C(0x90) || opcode == UINT8_C(0x91))
            && prefix == X86_SIMD_PREFIX_PF2)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0x90)) {
        form_id = (cdisasm_x86_form_id)(form_id
            + (modrm.is_register ? UINT16_C(0) : UINT16_C(2)));
    } else if (opcode == UINT8_C(0x91)) {
        form_id = (cdisasm_x86_form_id)(form_id + UINT16_C(4));
    } else if (opcode == UINT8_C(0x92)) {
        form_id = (cdisasm_x86_form_id)(form_id - UINT16_C(2));
    } else {
        form_id = (cdisasm_x86_form_id)(form_id - UINT16_C(4));
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)group_id;
    (void)form_id;
    (void)bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, X86_CAP_AMD64);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    decoder_require_extra(decoder, group_id);
    if (opcode == UINT8_C(0x90)) {
        if (!add_mask_register_operand_access(
                decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (modrm.is_register) {
            return add_mask_register_operand_access(
                decoder, modrm.rm3, bits, CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    if (opcode == UINT8_C(0x91)) {
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_WRITE)
            && add_mask_register_operand_access(
                decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ);
    }
    if (opcode == UINT8_C(0x92)) {
        return add_mask_register_operand_access(
                decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                decoder, modrm.rm, bits == 64u ? 64u : 32u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    return add_register_operand_access(
            decoder, modrm.reg, bits == 64u ? 64u : 32u,
            CDISASM_OPERAND_ACCESS_WRITE)
        && add_mask_register_operand_access(
            decoder, modrm.rm3, bits, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_evex_apx_movbe(
    x86_decoder *decoder, uint8_t p0, uint8_t p1, uint8_t p2,
    uint8_t opcode)
{
    const uint8_t prefix = p1 & UINT8_C(3);
    const uint8_t w = (p1 >> 7) & UINT8_C(1);
    const unsigned int bits = prefix == X86_SIMD_PREFIX_P66
        ? 16u : w != 0 ? 64u : 32u;
    x86_modrm modrm;

    if (decoder->mode != CDISASM_MODE_64
        || (prefix != X86_SIMD_PREFIX_NONE
            && prefix != X86_SIMD_PREFIX_P66)
        || (prefix == X86_SIMD_PREFIX_P66 && w != 0)
        || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)
        || p2 != UINT8_C(0x08)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->rex = (uint8_t)(w != 0 ? 8u : 0u);
    if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
    if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
    if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
    decoder->rex_present = 0;
    decoder->modrm_reg_high = (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    decoder->modrm_rm_high = (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
    decoder->address_base_high = decoder->modrm_rm_high;
    if ((p1 & UINT8_C(0x04)) == 0) decoder->address_index_high = 16u;
    if (!decode_modrm(decoder, &modrm)) return 0;
    if (modrm.is_register && (p1 & UINT8_C(0x04)) == 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    (void)bits;
    (void)opcode;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_MOVBE;
    decoder->form_id = modrm.is_register ? UINT16_C(1649)
        : opcode == UINT8_C(0x60) ? UINT16_C(1651) : UINT16_C(1653);
    decoder_require_caps(decoder, X86_CAP_AMD64);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_MOVBE);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_MOVBE);
    if (opcode == UINT8_C(0x60)) {
        if (!add_register_operand_access(
                decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (modrm.is_register) {
            return add_register_operand_access(
                decoder, modrm.rm, bits, CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    if (modrm.is_register) {
        return add_register_operand_access(
                decoder, modrm.rm, bits, CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ);
    }
    return add_rm_operand(decoder, &modrm, bits, 1)
        && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_WRITE)
        && add_register_operand_access(
            decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_evex_apx_invalidate(
    x86_decoder *decoder,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t opcode)
{
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    cdisasm_x86_group_id family_group;
    x86_modrm modrm;

    if (opcode == UINT8_C(0xf0)) {
        name_id = CDISASM_X86_NAME_INVEPT;
        form_id = UINT16_C(1408);
        family_group = CDISASM_X86_GROUP_APX_F_VMX;
    } else if (opcode == UINT8_C(0xf1)) {
        name_id = CDISASM_X86_NAME_INVVPID;
        form_id = UINT16_C(1417);
        family_group = CDISASM_X86_GROUP_APX_F_VMX;
    } else {
        name_id = CDISASM_X86_NAME_INVPCID;
        form_id = UINT16_C(1414);
        family_group = CDISASM_X86_GROUP_APX_F_INVPCID;
    }

    decoder->rex = 0;
    if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
    if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
    if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
    decoder->rex_present = 0;
    decoder->modrm_reg_high = (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    decoder->modrm_rm_high = (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
    decoder->address_base_high = decoder->modrm_rm_high;
    decoder->address_index_high = (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->mode != CDISASM_MODE_64
        || (p1 & UINT8_C(0xfb)) != UINT8_C(0x7a)
        || p2 != UINT8_C(0x08)
        || decoder->lock_prefix || decoder->repeat_prefix
        || decoder->operand_override
        || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0
        || modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    (void)family_group;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder->groups |= CDISASM_GROUP_PRIVILEGED;
    decoder_require_caps(decoder, X86_CAP_AMD64);
    if (name_id == CDISASM_X86_NAME_INVEPT) {
        decoder_require_caps(decoder, X86_CAP_VMX | X86_CAP_INVEPT);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_VMX);
    } else if (name_id == CDISASM_X86_NAME_INVVPID) {
        decoder_require_caps(decoder, X86_CAP_VMX | X86_CAP_INVVPID);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_VMX);
    } else {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_INVPCID);
    }
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    decoder_require_extra(decoder, family_group);
    return add_register_operand_access(
               decoder, modrm.reg, 64u, CDISASM_OPERAND_ACCESS_READ)
        && add_rm_operand(decoder, &modrm, 128u, 1)
        && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_evex(x86_decoder *decoder)
{
    uint8_t p0;
    uint8_t p1;
    uint8_t p2;
    uint8_t opcode;
    uint8_t map_select;
    uint8_t prefix;
    uint8_t w;
    uint8_t ll;
    uint8_t aaa;
    uint8_t apx_u0;
    uint8_t legacy_prefix_size = decoder->encoding.prefix_size;
    unsigned int source_index;
    unsigned int vector_bits;
    unsigned int destination_bits;
    unsigned int source_register_bits;
    unsigned int memory_bits;
    unsigned int broadcast_count;
    uint64_t immediate = 0;
    int has_imm8;
    int has_deferred_evex_legality;
    int is_owned_map1_vor;
    int is_owned_map1_vmul;
    int is_generated_map1_vpshuf;
    int is_generated_evex_packed_compare;
    int is_generated_evex_packed_compare_reserved;
    int is_owned_integer_minmax;
    int is_owned_gfni;
    int is_owned_compress_expand;
    int is_owned_vpternlog;
    int is_owned_map2_vpabs;
    int is_owned_map2_vp2intersect;
    int is_owned_vpack;
    int is_owned_map5_vmul;
    int is_apx_map5_vmul;
    int is_apx_map6_vgetexp16;
    int is_scalar;
    x86_evex_shape shape;
    x86_modrm modrm;
#if USE_EXTRA_OPCODES
    const x86_evex_descriptor *descriptor;
    cdisasm_operand_access destination_access;
#endif

    if (!read_u8(decoder, &p0)) {
        return 0;
    }
    if (decoder->mode != CDISASM_MODE_64
        && (p0 & UINT8_C(0xc0)) != UINT8_C(0xc0)) {
        /* 62 /r is legacy BOUND outside long mode. */
        --decoder->position;
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (modrm.is_register) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = CDISASM_X86_NAME_BOUND;
        return add_register_operand_access(
                   decoder, modrm.reg, decoder->operand_bits,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_rm_operand(
                   decoder, &modrm, decoder->operand_bits * 2u, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    if (!read_u8(decoder, &p1)
        || !read_u8(decoder, &p2)
        || !read_u8(decoder, &opcode)) {
        return 0;
    }
    map_select = p0 & UINT8_C(0x07);
    prefix = p1 & UINT8_C(0x03);

    /* APX-F CMPCCXADD occupies the EVEX map-2 E0..EF range.  The
     * handwritten EVEX vector decoder has no operand-builder for this
     * memory-only three-operand family; delegate the complete generated
     * descriptor matrix before generic EVEX legality can classify it as an
     * unknown vector form. */
    if (map_select == UINT8_C(2)
        && opcode >= UINT8_C(0xe0) && opcode <= UINT8_C(0xef)
        /* Native APX memory forms reuse EVEX.U as the inverted X4 bit;
         * ordinary AVX-512 EVEX forms require U=1.  Keep the delegation
         * narrow so valid non-APX vector forms retain their native path. */
        && (p1 & UINT8_C(0x04)) == 0u) {
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    is_generated_map1_vpshuf = map_select == UINT8_C(1)
        && opcode == UINT8_C(0x70)
        && prefix != X86_SIMD_PREFIX_NONE;
    is_generated_evex_packed_compare =
        (map_select == UINT8_C(1)
            && is_classic_packed_compare_opcode(opcode))
        || (map_select == UINT8_C(2) && opcode == UINT8_C(0x37));
    is_generated_evex_packed_compare_reserved =
        is_generated_evex_packed_compare
        && (prefix != X86_SIMD_PREFIX_P66
            || (p2 & UINT8_C(0x80)) != 0u
            || (p2 & UINT8_C(0x60)) == UINT8_C(0x60)
            || (map_select == UINT8_C(2)
                && (p1 & UINT8_C(0x80)) == 0u)
            || (map_select == UINT8_C(1)
                && (p1 & UINT8_C(0x80)) != 0u
                && (opcode == UINT8_C(0x66)
                    || opcode == UINT8_C(0x76)))
            || ((p2 & UINT8_C(0x10)) != 0u
                && (opcode == UINT8_C(0x64)
                    || opcode == UINT8_C(0x65)
                    || opcode == UINT8_C(0x74)
                    || opcode == UINT8_C(0x75)
                    || (decoder->position < decoder->code_size
                        && (decoder->code[decoder->position]
                            & UINT8_C(0xc0)) == UINT8_C(0xc0)))));
    is_owned_integer_minmax =
        is_packed_integer_minmax_opcode(map_select, opcode);
    is_owned_gfni = gfni_evex_opcode_owned(map_select, opcode);
    is_owned_compress_expand =
        compress_expand_evex_opcode_owned(map_select, opcode);
    is_owned_vpternlog = map_select == UINT8_C(3)
        && opcode == UINT8_C(0x25);
    has_deferred_evex_legality = (map_select == UINT8_C(1)
            && opcode == UINT8_C(0x56))
        || (map_select == UINT8_C(1)
            && (opcode == UINT8_C(0x63)
                || opcode == UINT8_C(0x67)
                || opcode == UINT8_C(0x6b)))
        || (map_select == UINT8_C(2) && opcode == UINT8_C(0x2b))
        || (map_select == UINT8_C(2)
            && opcode >= UINT8_C(0x1c) && opcode <= UINT8_C(0x1f))
        || (map_select == UINT8_C(2)
            && opcode == UINT8_C(0x68))
        || is_generated_evex_packed_compare_reserved
        || is_generated_map1_vpshuf
        || is_owned_integer_minmax
        || is_owned_gfni
        || is_owned_compress_expand
        || is_owned_vpternlog
        || (map_select == UINT8_C(3) && opcode == UINT8_C(0x42))
        || (prefix == X86_SIMD_PREFIX_P66
            && ((map_select == 1
                && (opcode == UINT8_C(0x71)
                    || opcode == UINT8_C(0x72)
                    || opcode == UINT8_C(0x73)))
            || ((map_select == 2 || map_select == 3)
                && opcode >= UINT8_C(0x70)
                && opcode <= UINT8_C(0x73))
            || (map_select == 2
                && (opcode == UINT8_C(0x75)
                    || opcode == UINT8_C(0x7d)
                    || opcode == UINT8_C(0x83)
                    || opcode == UINT8_C(0x8d)))));
    if ((decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override
            || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0)
        && !has_deferred_evex_legality) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (map_select == 0
        || (map_select > 6
            && !(map_select == UINT8_C(7)
                && (opcode == UINT8_C(0xf6)
                    || opcode == UINT8_C(0xf8))))
        || (map_select <= 3 && (p0 & UINT8_C(0x08)) != 0
            && decoder->mode != CDISASM_MODE_64
            && (!has_deferred_evex_legality
                || (map_select == UINT8_C(1)
                    && opcode == UINT8_C(0x56))
                || (map_select == UINT8_C(2)
                    && opcode == UINT8_C(0x68))))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->prefix_flags |= CDISASM_PREFIX_EVEX;
    decoder->encoding.prefix_size = (uint8_t)(legacy_prefix_size + 4u);
    decoder->encoding.opcode_offset = (uint8_t)(legacy_prefix_size + 4u);
    decoder->encoding.opcode_size = 1;

    if (map_select == UINT8_C(1)
        && opcode >= UINT8_C(0x90) && opcode <= UINT8_C(0x93)) {
        return decode_evex_apx_kmov(decoder, p0, p1, p2, opcode);
    }
    if (map_select == UINT8_C(4)
        && (opcode == UINT8_C(0x60) || opcode == UINT8_C(0x61))) {
        return decode_evex_apx_movbe(decoder, p0, p1, p2, opcode);
    }
    if (map_select == UINT8_C(4)
        && opcode >= UINT8_C(0xf0) && opcode <= UINT8_C(0xf2)
        && (p1 & UINT8_C(0x03)) == UINT8_C(0x02)) {
        return decode_evex_apx_invalidate(decoder, p0, p1, p2, opcode);
    }

    if (map_select == UINT8_C(2)
        && (opcode == UINT8_C(0xf2) || opcode == UINT8_C(0xf5)
            || opcode == UINT8_C(0xf7))
        && prefix == X86_SIMD_PREFIX_NONE) {
        const int is_bextr = opcode == UINT8_C(0xf7);
        const int is_bzhi = opcode == UINT8_C(0xf5);
        const uint8_t nf = (p2 & UINT8_C(0x04)) != 0;
        const unsigned int bits = (p1 & UINT8_C(0x80)) != 0 ? 64u : 32u;
        unsigned int source;

        if (decoder->mode != CDISASM_MODE_64
            || (p2 & UINT8_C(0xf3)) != 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        source = ((unsigned int)(~p1) >> 3) & 15u;
        source += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;

        decoder->rex = (uint8_t)(bits == 64u ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
        if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
        if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
        decoder->rex_present = 0;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high =
            (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
        if (!decode_modrm(decoder, &modrm)) return 0;
        if (modrm.is_register && (p1 & UINT8_C(0x04)) == 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }

#if !USE_EXTRA_OPCODES
        (void)is_bextr;
        (void)is_bzhi;
        (void)nf;
        (void)bits;
        (void)source;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = is_bextr
            ? CDISASM_X86_NAME_BEXTR
            : is_bzhi ? CDISASM_X86_NAME_BZHI : CDISASM_X86_NAME_ANDN;
        decoder->form_id = (cdisasm_x86_form_id)(
            (is_bextr ? UINT16_C(269)
                : is_bzhi ? UINT16_C(416) : UINT16_C(183))
            + (bits == 64u ? UINT16_C(4) : UINT16_C(0))
            + (modrm.is_register ? UINT16_C(0) : UINT16_C(2))
            + (nf != 0 ? UINT16_C(1) : UINT16_C(0)));
        if (nf != 0) decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
        decoder_require_caps(decoder, X86_CAP_AMD64);
        if (!is_bzhi) decoder_require_caps(decoder, X86_CAP_BMI1);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        decoder_require_extra(decoder, is_bzhi
            ? CDISASM_X86_GROUP_BMI2 : CDISASM_X86_GROUP_BMI1);
        decoder_require_extra(decoder, nf != 0
            ? (is_bzhi ? CDISASM_X86_GROUP_APX_F_BMI2_N3
                       : CDISASM_X86_GROUP_APX_F_BMI1_N3)
            : (is_bzhi ? CDISASM_X86_GROUP_APX_F_BMI2
                       : CDISASM_X86_GROUP_APX_F_BMI1));
        if (!add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        if (is_bextr || is_bzhi) {
            return add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                    decoder, CDISASM_OPERAND_ACCESS_READ)
                && add_register_operand_access(
                    decoder, source, bits,
                    CDISASM_OPERAND_ACCESS_READ);
        }
        return add_register_operand_access(
                decoder, source, bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (map_select == UINT8_C(2) && opcode == UINT8_C(0xf3)
        && prefix == X86_SIMD_PREFIX_NONE) {
        const uint8_t nf = (p2 & UINT8_C(0x04)) != 0;
        const unsigned int bits = (p1 & UINT8_C(0x80)) != 0 ? 64u : 32u;
        unsigned int destination;
        cdisasm_x86_name_id name_id;
        cdisasm_x86_form_id base_form;

        if (decoder->mode != CDISASM_MODE_64
            || (p0 & UINT8_C(0x90)) != UINT8_C(0x90)
            || (p2 & UINT8_C(0xf3)) != 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        destination = ((unsigned int)(~p1) >> 3) & 15u;
        destination += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;

        decoder->rex = (uint8_t)(bits == 64u ? 8u : 0u);
        if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
        if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
        decoder->rex_present = 0;
        decoder->modrm_reg_high = 0;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high =
            (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
        if (!decode_modrm(decoder, &modrm)) return 0;
        if (modrm.is_register && (p1 & UINT8_C(0x04)) == 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (modrm.reg3 == 1u) {
            name_id = CDISASM_X86_NAME_BLSR;
            base_form = UINT16_C(345);
        } else if (modrm.reg3 == 2u) {
            name_id = CDISASM_X86_NAME_BLSMSK;
            base_form = UINT16_C(333);
        } else if (modrm.reg3 == 3u) {
            name_id = CDISASM_X86_NAME_BLSI;
            base_form = UINT16_C(321);
        } else {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }

#if !USE_EXTRA_OPCODES
        (void)nf;
        (void)bits;
        (void)destination;
        (void)name_id;
        (void)base_form;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = name_id;
        decoder->form_id = (cdisasm_x86_form_id)(
            base_form + (bits == 64u ? UINT16_C(4) : UINT16_C(0))
            + (modrm.is_register ? UINT16_C(0) : UINT16_C(2))
            + (nf != 0 ? UINT16_C(1) : UINT16_C(0)));
        if (nf != 0) decoder->prefix_flags |= CDISASM_PREFIX_APX_NF;
        decoder_require_caps(decoder, X86_CAP_AMD64 | X86_CAP_BMI1);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_BMI1);
        decoder_require_extra(decoder, nf != 0
            ? CDISASM_X86_GROUP_APX_F_BMI1_N3
            : CDISASM_X86_GROUP_APX_F_BMI1);
        return add_register_operand_access(
                decoder, destination, bits,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (map_select == UINT8_C(2)
        && ((opcode == UINT8_C(0xf5)
                && (prefix == X86_SIMD_PREFIX_PF2
                    || prefix == X86_SIMD_PREFIX_PF3))
            || (opcode == UINT8_C(0xf6)
                && prefix == X86_SIMD_PREFIX_PF2))) {
        const int is_mulx = opcode == UINT8_C(0xf6);
        const int is_pext = prefix == X86_SIMD_PREFIX_PF3;
        const unsigned int bits = (p1 & UINT8_C(0x80)) != 0 ? 64u : 32u;
        unsigned int source;

        if (decoder->mode != CDISASM_MODE_64
            || (p2 & UINT8_C(0xf7)) != 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        source = ((unsigned int)(~p1) >> 3) & 15u;
        source += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;

        decoder->rex = (uint8_t)(bits == 64u ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
        if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
        if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
        decoder->rex_present = 0;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high =
            (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
        if (!decode_modrm(decoder, &modrm)) return 0;
        if (modrm.is_register && (p1 & UINT8_C(0x04)) == 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }

#if !USE_EXTRA_OPCODES
        (void)is_mulx;
        (void)is_pext;
        (void)bits;
        (void)source;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = is_mulx
            ? CDISASM_X86_NAME_MULX
            : is_pext ? CDISASM_X86_NAME_PEXT : CDISASM_X86_NAME_PDEP;
        decoder->form_id = (cdisasm_x86_form_id)(
            (is_mulx ? UINT16_C(1803)
                : is_pext ? UINT16_C(2106) : UINT16_C(2088))
            + (bits == 64u ? UINT16_C(2) : UINT16_C(0))
            + (modrm.is_register ? UINT16_C(0) : UINT16_C(1)));
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_BMI2);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_BMI2);
        return add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                decoder, source, bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (map_select == UINT8_C(2) && opcode == UINT8_C(0xf7)
        && prefix != X86_SIMD_PREFIX_NONE) {
        const unsigned int bits = (p1 & UINT8_C(0x80)) != 0 ? 64u : 32u;
        unsigned int count_register;
        cdisasm_x86_name_id name_id;
        cdisasm_x86_form_id base_form;

        if (decoder->mode != CDISASM_MODE_64
            || (p2 & UINT8_C(0xf7)) != 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        count_register = ((unsigned int)(~p1) >> 3) & 15u;
        count_register += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;

        decoder->rex = (uint8_t)(bits == 64u ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
        if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
        if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
        decoder->rex_present = 0;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high =
            (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
        if (!decode_modrm(decoder, &modrm)) return 0;
        if (modrm.is_register && (p1 & UINT8_C(0x04)) == 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (prefix == X86_SIMD_PREFIX_P66) {
            name_id = CDISASM_X86_NAME_SHLX;
            base_form = UINT16_C(3000);
        } else if (prefix == X86_SIMD_PREFIX_PF3) {
            name_id = CDISASM_X86_NAME_SARX;
            base_form = UINT16_C(2756);
        } else {
            name_id = CDISASM_X86_NAME_SHRX;
            base_form = UINT16_C(3084);
        }

#if !USE_EXTRA_OPCODES
        (void)bits;
        (void)count_register;
        (void)name_id;
        (void)base_form;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = name_id;
        decoder->form_id = (cdisasm_x86_form_id)(
            base_form + (bits == 64u ? UINT16_C(2) : UINT16_C(0))
            + (modrm.is_register ? UINT16_C(0) : UINT16_C(1)));
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_BMI2);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_BMI2);
        return add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ)
            && add_register_operand_access(
                decoder, count_register, bits,
                CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (map_select == UINT8_C(3) && opcode == UINT8_C(0xf0)
        && prefix == X86_SIMD_PREFIX_PF2) {
        const unsigned int bits = (p1 & UINT8_C(0x80)) != 0 ? 64u : 32u;
        uint64_t rorx_immediate;

        if (decoder->mode != CDISASM_MODE_64
            || (p1 & UINT8_C(0x78)) != UINT8_C(0x78)
            || p2 != UINT8_C(0x08)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->rex = (uint8_t)(bits == 64u ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0) decoder->rex |= UINT8_C(4);
        if ((p0 & UINT8_C(0x40)) == 0) decoder->rex |= UINT8_C(2);
        if ((p0 & UINT8_C(0x20)) == 0) decoder->rex |= UINT8_C(1);
        decoder->rex_present = 0;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0 ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high =
            (p1 & UINT8_C(0x04)) == 0 ? 16u : 0u;
        if (!decode_modrm(decoder, &modrm)) return 0;
        if (modrm.is_register && (p1 & UINT8_C(0x04)) == 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!read_immediate_value(decoder, 8u, &rorx_immediate)) return 0;

#if !USE_EXTRA_OPCODES
        (void)bits;
        (void)rorx_immediate;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_RORX;
        decoder->form_id = (cdisasm_x86_form_id)(
            UINT16_C(2684) + (bits == 64u ? UINT16_C(2) : UINT16_C(0))
            + (modrm.is_register ? UINT16_C(0) : UINT16_C(1)));
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_BMI2);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F_BMI2);
        return add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ)
            && add_immediate_value(decoder, 8u, rorx_immediate, 0);
#endif
    }

    {
        const int msr_imm_result = decode_msr_imm_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (msr_imm_result >= 0) {
            return msr_imm_result;
        }
    }

    {
        const int user_msr_result = decode_user_msr_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (user_msr_result >= 0) {
            return user_msr_result;
        }
    }

    if (map_select == 4) {
        return decode_apx_evex(decoder, p0, p1, p2, opcode);
    }

    {
        const int gfni_result = decode_gfni_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (gfni_result >= 0) {
            return gfni_result;
        }
    }

    {
        const int vptest_mask_result = decode_vptest_mask_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (vptest_mask_result >= 0) {
            return vptest_mask_result;
        }
    }

    {
        const int vpternlog_result = decode_vpternlog_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (vpternlog_result >= 0) {
            return vpternlog_result;
        }
    }

    apx_u0 = (p1 & UINT8_C(0x04)) == 0;
    w = (p1 & UINT8_C(0x80)) != 0;
    ll = (p2 >> 5) & UINT8_C(0x03);
    aaa = p2 & UINT8_C(0x07);
    source_index = ((unsigned int)(~p1) >> 3) & 15u;
    source_index += (p2 & UINT8_C(0x08)) == 0 ? 16u : 0u;

    {
        const int move_result = decode_vector_move_quadword_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (move_result >= 0) {
            return move_result;
        }
    }

    {
        const int move_result = decode_vector_move_word_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (move_result >= 0) {
            return move_result;
        }
    }

    {
        const int packed_move_result = decode_unaligned_packed_move_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (packed_move_result >= 0) {
            return packed_move_result;
        }
    }

    {
        const int duplicate_result = decode_vector_duplicate_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (duplicate_result >= 0) {
            return duplicate_result;
        }
    }

    {
        const int scalar_move_result =
            decode_vector_move_scalar_evex(
                decoder, p0, p1, p2, map_select, opcode);

        if (scalar_move_result >= 0) {
            return scalar_move_result;
        }
    }

    {
        const int movrs_result = decode_vector_move_read_shared_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (movrs_result >= 0) {
            return movrs_result;
        }
    }

    {
        const int non_temporal_result =
            decode_non_temporal_aligned_load_evex(
                decoder, p0, p1, p2, map_select, opcode);

        if (non_temporal_result >= 0) {
            return non_temporal_result;
        }
    }

    {
        const int non_temporal_result =
            decode_non_temporal_vector_store_evex(
                decoder, p0, p1, p2, map_select, opcode);

        if (non_temporal_result >= 0) {
            return non_temporal_result;
        }
    }
    {
        const int vdbpsadbw_result = decode_vdbpsadbw_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (vdbpsadbw_result >= 0) {
            return vdbpsadbw_result;
        }
    }
    {
        const int vmpsadbw_result = decode_vmpsadbw_evex(
            decoder, p0, p1, p2, map_select, opcode);

        if (vmpsadbw_result >= 0) {
            return vmpsadbw_result;
        }
    }
    is_owned_map1_vor = map_select == 1
        && opcode == UINT8_C(0x56);
    is_owned_map1_vmul = map_select == 1
        && opcode == UINT8_C(0x59);
    is_owned_map2_vpabs = map_select == 2
        && opcode >= UINT8_C(0x1c) && opcode <= UINT8_C(0x1f);
    is_owned_map2_vp2intersect = map_select == 2
        && opcode == UINT8_C(0x68);
    is_owned_vpack = (map_select == 1
            && (opcode == UINT8_C(0x63)
                || opcode == UINT8_C(0x67)
                || opcode == UINT8_C(0x6b)))
        || (map_select == 2 && opcode == UINT8_C(0x2b));
    is_owned_map5_vmul = map_select == 5
        && opcode == UINT8_C(0x59)
        && prefix != X86_SIMD_PREFIX_PF2;
    is_apx_map5_vmul = is_owned_map5_vmul && w == 0;
    is_apx_map6_vgetexp16 = map_select == 6 && w == 0
        && ((opcode == UINT8_C(0x42)
                && (prefix == X86_SIMD_PREFIX_NONE
                    || prefix == X86_SIMD_PREFIX_P66))
            || (opcode == UINT8_C(0x43)
                && prefix == X86_SIMD_PREFIX_P66));

    if (is_generated_evex_packed_compare_reserved) {
        /* These generated EVEX mask-destination compares require pp=66 and
         * never permit zeroing or LL=3.  Byte/word forms have no broadcast;
         * dword forms require W=0, qword VPCMPGTQ requires W=1, and b=1 is
         * reserved with a register source.  Consume the complete ModRM/EA
         * before rejecting. */
        decoder->rex = (uint8_t)(w ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0u) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0u) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->rex_present = 0u;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0u ? 16u : 0u;
        if ((p0 & UINT8_C(0x08)) != 0u) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        if (apx_u0) {
            decoder->address_index_high = 16u;
        }
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (is_generated_evex_packed_compare && apx_u0) {
        /* U=0 is the APX X4 memory-address extension for these generated
         * EVEX compares.  The hand decoder does not otherwise own their
         * allocated shapes, but it must consume the complete address before
         * deciding the structural register/mode exclusions and delegating a
         * valid memory form to the generated decoder. */
        decoder->rex = (uint8_t)(w ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0u) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0u) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->rex_present = 0u;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0u ? 16u : 0u;
        if ((p0 & UINT8_C(0x08)) != 0u) {
            decoder->modrm_rm_high = 16u;
            decoder->address_base_high = 16u;
        }
        decoder->address_index_high = 16u;
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (decoder->mode != CDISASM_MODE_64 || modrm.is_register) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    if (is_generated_map1_vpshuf) {
        /* Generated VPSHUFD/HW/LW owns an imm8 after every ModRM/EA.  Parse
         * the complete payload here so truncation wins before classifying a
         * reserved control or handing the encoding to the generated
         * decoder.  Keeping this structural ownership in the core also
         * preserves status behavior when optional opcode tables are off. */
        decoder->rex = (uint8_t)(w ? 8u : 0u);
        if ((p0 & UINT8_C(0x80)) == 0u) {
            decoder->rex |= UINT8_C(4);
        }
        if ((p0 & UINT8_C(0x40)) == 0u) {
            decoder->rex |= UINT8_C(2);
        }
        if ((p0 & UINT8_C(0x20)) == 0u) {
            decoder->rex |= UINT8_C(1);
        }
        decoder->rex_present = 0u;
        decoder->modrm_reg_high =
            (p0 & UINT8_C(0x10)) == 0u ? 16u : 0u;
        decoder->modrm_rm_high =
            (p0 & UINT8_C(0x08)) != 0u ? 16u : 0u;
        decoder->address_base_high = decoder->modrm_rm_high;
        decoder->address_index_high = apx_u0 ? 16u : 0u;
        if (!decode_modrm(decoder, &modrm)
            || !read_immediate_value(decoder, 8u, &immediate)) {
            return 0;
        }
        if (((apx_u0 || (p0 & UINT8_C(0x08)) != 0u)
                && decoder->mode != CDISASM_MODE_64)
            || (apx_u0 && modrm.is_register)
            || decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override
            || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0u
            || ll == 3u
            || ((p2 & UINT8_C(0x80)) != 0u && aaa == 0u)
            || source_index != 0u
            || (prefix == X86_SIMD_PREFIX_P66 && w != 0u)
            || ((p2 & UINT8_C(0x10)) != 0u
                && (prefix != X86_SIMD_PREFIX_P66
                    || modrm.is_register))) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    if (apx_u0
        && !(map_select == 2
            && prefix == X86_SIMD_PREFIX_P66
            && ((opcode == UINT8_C(0x14)
                    || opcode == UINT8_C(0x15)
                    || opcode == UINT8_C(0x45)
                    || opcode == UINT8_C(0x46)
                    || opcode == UINT8_C(0x47))
                || (w != 0
                    && (opcode == UINT8_C(0x10)
                        || opcode == UINT8_C(0x11)
                        || opcode == UINT8_C(0x12)))
                || opcode == UINT8_C(0x62)
                || opcode == UINT8_C(0x63)
                || opcode == UINT8_C(0x54)
                || opcode == UINT8_C(0x55)
                || opcode == UINT8_C(0x44)
                || opcode == UINT8_C(0xc4)
                || opcode == UINT8_C(0x88)
                || opcode == UINT8_C(0x89)
                || opcode == UINT8_C(0x8a)
                || opcode == UINT8_C(0x8b)
                || opcode == UINT8_C(0x8f)
                || opcode == UINT8_C(0x75)
                || opcode == UINT8_C(0x7d)
                || opcode == UINT8_C(0x8d)
                || opcode == UINT8_C(0x83)
                || (opcode >= UINT8_C(0x50)
                    && opcode <= UINT8_C(0x53))))
            && !(map_select == 2
                && prefix != X86_SIMD_PREFIX_P66
                && (opcode == UINT8_C(0x50)
                    || opcode == UINT8_C(0x51)))
            && !(map_select == 1
                && prefix == X86_SIMD_PREFIX_P66
                && (opcode == UINT8_C(0x71) || opcode == UINT8_C(0x72)
                    || opcode == UINT8_C(0x73)))
            && !((map_select == 2 || map_select == 3)
                && prefix == X86_SIMD_PREFIX_P66
                && opcode >= UINT8_C(0x70)
                && opcode <= UINT8_C(0x73))
            && !(map_select == 1
                && prefix == X86_SIMD_PREFIX_P66
                && is_classic_modular_add_sub_opcode(opcode))
            && !is_owned_integer_minmax
            && !is_owned_map1_vor
            && !is_owned_map1_vmul
            && !is_owned_map2_vpabs
            && !is_owned_map2_vp2intersect
            && !is_owned_vpack
            && !is_owned_map5_vmul
            && !is_apx_map6_vgetexp16) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    {
        const int ace_result = decode_ace_bsr_evex(
            decoder, p0, p1, p2, map_select, opcode,
            prefix, w, ll, aaa);

        if (ace_result >= 0) {
            return ace_result;
        }
    }

    {
        const int ace_result = decode_ace_tilemov_evex(
            decoder, p0, p1, p2, map_select, opcode,
            prefix, w, ll, aaa);

        if (ace_result >= 0) {
            return ace_result;
        }
    }

    {
        const int ace_result = decode_ace_top_evex(
            decoder, p0, p1, p2, map_select, opcode,
            prefix, w, ll, aaa);

        if (ace_result >= 0) {
            return ace_result;
        }
    }

    {
        const int amx_result = decode_apx_amx_memory_evex(
            decoder, p0, p1, p2, map_select, opcode,
            prefix, w, ll, aaa);

        if (amx_result >= 0) {
            return amx_result;
        }
    }

    {
        const int amx_result = decode_amx_row_evex(
            decoder, p0, p1, p2, map_select, opcode,
            prefix, w, ll, aaa);

        if (amx_result >= 0) {
            return amx_result;
        }
    }

    if (!evex_shape_for_encoding(map_select, opcode, prefix, w, &shape)) {
        return decoder_fail(decoder, apx_u0
            ? CDISASM_STATUS_INVALID_INSTRUCTION
            : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    /* EVEX.U=0 is ordinarily reserved.  APX reinterprets it as inverted
     * X4 for memory addressing.  This ownership covers the complete packed
     * shift/rotate tranches, the map-2/map-3 VBMI2 double shifts, the exact
     * MAP1 FP32/FP64 logical OR and multiply, MAP5 FP16/BF16 multiply and
     * MAP6 16-bit GETEXP allocations; register forms and
     * every other descriptor remain structurally invalid. */
    if (apx_u0
        && !is_owned_map1_vor
        && !is_owned_map1_vmul
        && !is_owned_map2_vpabs
        && !is_owned_map2_vp2intersect
        && !is_owned_vpack
        && !is_owned_map5_vmul
        && !is_apx_map6_vgetexp16
        && shape.form != X86_EVEX_FORM_PACKED_INTEGER_MINMAX
        && shape.form != X86_EVEX_FORM_PACKED_INTEGER_ADD_SUB
        && shape.form
            != X86_EVEX_FORM_PACKED_INTEGER_VARIABLE_SHIFT
        && shape.form
            != X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
        && shape.form != X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE
        && shape.form != X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
        && shape.form != X86_EVEX_FORM_COMPRESS
        && shape.form != X86_EVEX_FORM_EXPAND
        && shape.form != X86_EVEX_FORM_POPCOUNT
        && shape.form != X86_EVEX_FORM_BITALG_MASK_DESTINATION
        && shape.form != X86_EVEX_FORM_VNNI_DOT_PRODUCT
        && shape.form != X86_EVEX_FORM_PERMUTE_TERNARY) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    has_imm8 = shape.form == X86_EVEX_FORM_NDS_VECTOR_IMM8
        || shape.form == X86_EVEX_FORM_COMPARE_MASK_IMM8
        || shape.form == X86_EVEX_FORM_EXTRACT_HALF_IMM8
        || shape.form == X86_EVEX_FORM_EXTRACT_QUARTER_IMM8
        || shape.form
            == X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
        || shape.form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE;
    is_scalar = shape.form == X86_EVEX_FORM_NDS_SCALAR
        || shape.form == X86_EVEX_FORM_4FMAPS_SCALAR;
    if (shape.form
            != X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
        && shape.form != X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE
        && shape.form != X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
        && shape.form != X86_EVEX_FORM_PERMUTE_TERNARY
        && shape.form != X86_EVEX_FORM_4VNNIW
        && shape.form != X86_EVEX_FORM_4FMAPS_PACKED
        && shape.form != X86_EVEX_FORM_4FMAPS_SCALAR
        && (((shape.w != 2 && shape.w != w)
                && !is_owned_map1_vor
                && !is_owned_map1_vmul
                && !is_owned_map2_vpabs
                && !is_owned_vpack
                && !is_owned_map5_vmul)
        || ((shape.form == X86_EVEX_FORM_UNARY_VECTOR
                || shape.form == X86_EVEX_FORM_UNARY_WIDEN
                || shape.form == X86_EVEX_FORM_UNARY_NARROW
                || shape.form == X86_EVEX_FORM_MEMORY_BROADCAST_BLOCK
                || shape.form == X86_EVEX_FORM_QWORD_XMM_BROADCAST
                || shape.form == X86_EVEX_FORM_EXTRACT_HALF_IMM8
                || shape.form == X86_EVEX_FORM_EXTRACT_QUARTER_IMM8
                || shape.form == X86_EVEX_FORM_COMPRESS
                || shape.form == X86_EVEX_FORM_EXPAND
                || shape.form == X86_EVEX_FORM_POPCOUNT
                || shape.form == X86_EVEX_FORM_MASK_BROADCAST)
            && source_index != 0 && !is_owned_map2_vpabs)
        || (shape.form == X86_EVEX_FORM_BITALG_MASK_DESTINATION
            && ((p0 & UINT8_C(0x90)) != UINT8_C(0x90)
                || (p2 & UINT8_C(0x80)) != 0))
        || (((p2 & UINT8_C(0x80)) != 0
                && (aaa == 0
                    || shape.form == X86_EVEX_FORM_COMPARE_MASK_IMM8))
            && !is_owned_map1_vor
            && !is_owned_map1_vmul
            && !is_owned_map2_vpabs
            && !is_owned_map2_vp2intersect
            && !is_owned_vpack
            && !is_owned_map5_vmul)
        || (shape.form == X86_EVEX_FORM_COMPARE_MASK_IMM8
            && (p0 & UINT8_C(0x90)) != UINT8_C(0x90))
        || (aaa != 0 && (shape.flags & X86_EVEX_FLAG_MASK) == 0
            && !is_owned_map2_vp2intersect))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->rex = (uint8_t)(w ? 8u : 0u);
    if ((p0 & UINT8_C(0x80)) == 0) {
        decoder->rex |= 4u;
    }
    if ((p0 & UINT8_C(0x40)) == 0) {
        decoder->rex |= 2u;
    }
    if ((p0 & UINT8_C(0x20)) == 0) {
        decoder->rex |= 1u;
    }
    decoder->rex_present = 0;
    decoder->modrm_reg_high = (p0 & UINT8_C(0x10)) == 0 ? 16u : 0u;
    if ((is_owned_map1_vor || is_owned_map2_vpabs
            || is_owned_vpack || is_owned_compress_expand
            || is_owned_map2_vp2intersect)
        && decoder->mode != CDISASM_MODE_64) {
        /* Once 62 has been distinguished from BOUND, these classic rows
         * ignore ordinary EVEX.B and the high vvvv bit outside long mode.
         * VP2INTERSECT's R/R' fields and V' remain fixed and are checked
         * after the complete address has been consumed. */
        decoder->rex &= (uint8_t)~UINT8_C(0x01);
        decoder->modrm_reg_high = 0;
    }
    if ((p0 & UINT8_C(0x08)) != 0) {
        decoder->modrm_rm_high = 16u;
        decoder->address_base_high = 16u;
    }
    if (apx_u0) {
        decoder->address_index_high = 16u;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    /* The allocated VOR and VMUL opcode rows consume their complete payloads:
     * MAP1 VOR owns the none/66 packed selectors, while
     * MAP1 selects VMULPS/PD/SS/SD while MAP5 selects
     * VMULPH/VMULBF16/VMULSH and deliberately leaves pp=F2 unowned.
     * Consume the complete ModRM/SIB/displacement payload before classifying
     * reserved W and EVEX.z-with-k0 controls so truncation keeps precedence. */
    if ((is_owned_map1_vor || is_owned_map1_vmul
            || is_owned_map2_vpabs || is_owned_map2_vp2intersect
            || is_owned_vpack
            || is_owned_map5_vmul)
        && ((is_owned_map1_vor
                && prefix != X86_SIMD_PREFIX_NONE
                && prefix != X86_SIMD_PREFIX_P66)
            || (is_owned_map2_vp2intersect
                && prefix != X86_SIMD_PREFIX_PF2)
            || (is_owned_map2_vpabs
                && prefix != X86_SIMD_PREFIX_P66)
            || (is_owned_vpack
                && prefix != X86_SIMD_PREFIX_P66)
            || (is_owned_map1_vor
                && (decoder->lock_prefix || decoder->repeat_prefix
                    || decoder->operand_override
                    || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0))
            || (is_owned_map2_vp2intersect
                && (decoder->lock_prefix || decoder->repeat_prefix
                    || decoder->operand_override
                    || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0))
            || (is_owned_map2_vpabs
                && (decoder->lock_prefix || decoder->repeat_prefix
                    || decoder->operand_override
                    || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0))
            || (is_owned_vpack
                && (decoder->lock_prefix || decoder->repeat_prefix
                    || decoder->operand_override
                    || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0))
            || (shape.w != 2 && shape.w != w)
            || (is_owned_map1_vor
                && decoder->mode != CDISASM_MODE_64
                && (p2 & UINT8_C(0x08)) == 0)
            || (is_owned_map2_vp2intersect
                && decoder->mode != CDISASM_MODE_64
                && (p2 & UINT8_C(0x08)) == 0)
            || (is_owned_map2_vpabs && source_index != 0)
            || (is_owned_vpack
                && decoder->mode != CDISASM_MODE_64
                && (p2 & UINT8_C(0x08)) == 0)
            || (is_owned_map2_vp2intersect
                && (p0 & UINT8_C(0x90)) != UINT8_C(0x90))
            || (is_owned_map2_vp2intersect
                && (aaa != 0 || (p2 & UINT8_C(0x80)) != 0))
            || ((p2 & UINT8_C(0x80)) != 0 && aaa == 0))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((is_owned_map1_vor || is_owned_map2_vp2intersect
            || is_owned_vpack || is_owned_compress_expand)
        && decoder->mode != CDISASM_MODE_64) {
        source_index &= 7u;
    }
    /* VPBROADCASTMB2Q/MW2D own only ModRM.mod=3.  Decode a complete
     * addressing payload first so truncated SIB/displacement data retains
     * precedence over the reserved memory-form classification. */
    if (shape.form == X86_EVEX_FORM_MASK_BROADCAST
        && !modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (shape.form == X86_EVEX_FORM_MEMORY_BROADCAST_BLOCK
        && (modrm.is_register || ll == 0u
            || ((opcode & UINT8_C(1)) != 0u && ll != 2u)
            || (p2 & UINT8_C(0x10)) != 0u)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (shape.form == X86_EVEX_FORM_QWORD_XMM_BROADCAST
        && ((opcode == UINT8_C(0x19) && ll == 0u)
            || (p2 & UINT8_C(0x10)) != 0u)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (shape.form == X86_EVEX_FORM_EXTRACT_HALF_IMM8
        && (ll != 2u || (!modrm.is_register
                && (p2 & UINT8_C(0x80)) != 0u))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (shape.form == X86_EVEX_FORM_EXTRACT_QUARTER_IMM8
        && (ll == 0u || (!modrm.is_register
                && (p2 & UINT8_C(0x80)) != 0u))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    /* Knights Mill multisource-four forms own only Tuple1_4X memory
     * sources.  Packed forms require VL512; 4FMAPS scalar forms are LLIG
     * (except the globally reserved LL=3 control) with fixed XMM operands.
     * Consume the addressing payload before reserved-form classification. */
    if ((shape.form == X86_EVEX_FORM_4VNNIW
            || shape.form == X86_EVEX_FORM_4FMAPS_PACKED
            || shape.form == X86_EVEX_FORM_4FMAPS_SCALAR)
        && (modrm.is_register
            || ((shape.form == X86_EVEX_FORM_4VNNIW
                    || shape.form == X86_EVEX_FORM_4FMAPS_PACKED)
                && ll != 2u)
            || (p2 & UINT8_C(0x10)) != 0
            || (p0 & UINT8_C(0x08)) != 0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    /* Opcode 73 carries both Qword and 128-bit DQ-lane shifts.  The opcode
     * shape is selected before ModRM, while this class's element width and
     * EVEX.b permission are selected by ModRM.reg. */
    if (shape.form
            == X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
        && opcode == UINT8_C(0x73)
        && (modrm.reg3 == 2u || modrm.reg3 == 6u)) {
        shape.w = 1u;
        shape.element_bits = 64u;
        shape.flags |= X86_EVEX_FLAG_BROADCAST;
    } else if (shape.form
            == X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
        && opcode == UINT8_C(0x73)
        && (modrm.reg3 == 3u || modrm.reg3 == 7u)) {
        shape.flags &= (uint8_t)~X86_EVEX_FLAG_MASK;
    }
    /* Opcodes 71, 72 and 73 own an imm8 for every ModRM.reg selector.  Once the complete
     * ModRM/SIB/displacement has been consumed, truncation of that immediate
     * takes precedence over every EVEX reserved-control classification. */
    if ((shape.form
                == X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
            || shape.form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE)
        && !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if ((shape.form == X86_EVEX_FORM_PACKED_INTEGER_MINMAX
            || shape.form
                == X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
            || shape.form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE
            || shape.form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
            || shape.form == X86_EVEX_FORM_COMPRESS
            || shape.form == X86_EVEX_FORM_EXPAND
            || shape.form == X86_EVEX_FORM_POPCOUNT
            || shape.form == X86_EVEX_FORM_BITALG_MASK_DESTINATION
            || shape.form == X86_EVEX_FORM_MASK_BROADCAST
            || shape.form == X86_EVEX_FORM_VNNI_DOT_PRODUCT
            || shape.form == X86_EVEX_FORM_4VNNIW
            || shape.form == X86_EVEX_FORM_4FMAPS_PACKED
            || shape.form == X86_EVEX_FORM_4FMAPS_SCALAR
            || shape.form == X86_EVEX_FORM_PERMUTE_TERNARY)
        && (decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override
            || (decoder->prefix_flags & CDISASM_PREFIX_REX) != 0
            || (shape.w != 2 && shape.w != w)
            || ((p2 & UINT8_C(0x80)) != 0 && aaa == 0)
            || (aaa != 0 && (shape.flags & X86_EVEX_FLAG_MASK) == 0))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (shape.form == X86_EVEX_FORM_COMPRESS
        && !modrm.is_register && (p2 & UINT8_C(0x80)) != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (apx_u0
        && (decoder->mode != CDISASM_MODE_64 || modrm.is_register)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((p0 & UINT8_C(0x08)) != 0
        && (is_owned_map1_vor
            || is_owned_map1_vmul
            || is_owned_map2_vpabs
            || is_owned_map2_vp2intersect
            || is_owned_vpack
            || is_apx_map5_vmul
            || shape.form == X86_EVEX_FORM_PACKED_INTEGER_MINMAX
            || shape.form == X86_EVEX_FORM_PACKED_INTEGER_ADD_SUB
            || shape.form == X86_EVEX_FORM_PACKED_INTEGER_LOGICAL
            || shape.form == X86_EVEX_FORM_PACKED_INTEGER_AVERAGE
            || shape.form
                == X86_EVEX_FORM_PACKED_INTEGER_VARIABLE_SHIFT
            || shape.form
                == X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
            || shape.form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE
            || shape.form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
            || shape.form == X86_EVEX_FORM_COMPRESS
            || shape.form == X86_EVEX_FORM_EXPAND
            || shape.form == X86_EVEX_FORM_POPCOUNT
            || shape.form == X86_EVEX_FORM_BITALG_MASK_DESTINATION
            || shape.form == X86_EVEX_FORM_MASK_BROADCAST
            || shape.form == X86_EVEX_FORM_VNNI_DOT_PRODUCT
            || shape.form == X86_EVEX_FORM_PERMUTE_TERNARY)
        && decoder->mode != CDISASM_MODE_64) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (modrm.is_register && (p0 & UINT8_C(0x08)) != 0) {
        if (!is_owned_map1_vor
            && !is_owned_map1_vmul
            && !is_owned_map2_vpabs
            && !is_owned_map2_vp2intersect
            && !is_owned_vpack
            && !is_apx_map5_vmul
            && shape.form != X86_EVEX_FORM_PACKED_INTEGER_MINMAX
            && shape.form != X86_EVEX_FORM_PACKED_INTEGER_ADD_SUB
            && shape.form != X86_EVEX_FORM_PACKED_INTEGER_LOGICAL
            && shape.form != X86_EVEX_FORM_PACKED_INTEGER_AVERAGE
            && shape.form
                != X86_EVEX_FORM_PACKED_INTEGER_VARIABLE_SHIFT
            && shape.form
                != X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
            && shape.form != X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE
            && shape.form != X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
            && shape.form != X86_EVEX_FORM_COMPRESS
            && shape.form != X86_EVEX_FORM_EXPAND
            && shape.form != X86_EVEX_FORM_POPCOUNT
            && shape.form != X86_EVEX_FORM_BITALG_MASK_DESTINATION
            && shape.form != X86_EVEX_FORM_MASK_BROADCAST
            && shape.form != X86_EVEX_FORM_VNNI_DOT_PRODUCT
            && shape.form != X86_EVEX_FORM_PERMUTE_TERNARY) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        /* APX P0.B4 qualifies the encoding but does not extend a vector
         * ModRM.rm register.  decode_modrm used the same bit for the memory
         * address path, so remove that provisional EGPR contribution here;
         * the ordinary EVEX B/X fields below still select ZMM0--ZMM31. */
        modrm.rm = (uint8_t)(modrm.rm - 16u);
    }
    if (modrm.is_register && (p0 & UINT8_C(0x40)) == 0) {
        modrm.rm = (uint8_t)(modrm.rm + 16u);
    }
    if (decoder->mode != CDISASM_MODE_64
        && (((p0 & UINT8_C(0xf0)) != UINT8_C(0xf0)
                && !is_owned_map1_vor
                && !is_owned_map2_vpabs
                && !is_owned_map2_vp2intersect
                && !is_owned_vpack
                && !is_owned_compress_expand)
            || (p2 & UINT8_C(0x08)) == 0
            || modrm.reg >= 8 || source_index >= 8
            || (modrm.is_register && modrm.rm >= 8)
            || (modrm.base >= 8 && modrm.base >= 0)
            || (modrm.index >= 8 && modrm.index >= 0))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((p2 & UINT8_C(0x10)) != 0) {
        if (modrm.is_register) {
            if ((shape.flags & (X86_EVEX_FLAG_ROUND
                    | X86_EVEX_FLAG_SAE
                    | X86_EVEX_FLAG_B_IGNORED)) == 0) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            vector_bits = is_scalar ? 128u : 512u;
        } else {
            if ((shape.flags & X86_EVEX_FLAG_BROADCAST) == 0
                || ll == 3) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            vector_bits = 128u << ll;
        }
    } else {
        if (ll == 3) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        vector_bits = is_scalar ? 128u : 128u << ll;
    }
    destination_bits = vector_bits;
    source_register_bits = vector_bits;
    if (is_scalar) {
        destination_bits = 128u;
        source_register_bits = 128u;
    } else if (shape.form == X86_EVEX_FORM_UNARY_WIDEN) {
        source_register_bits = vector_bits == 128u
            ? 128u : vector_bits / 2u;
    } else if (shape.form == X86_EVEX_FORM_UNARY_NARROW) {
        destination_bits = vector_bits == 512u ? 256u : 128u;
    } else if (shape.form == X86_EVEX_FORM_QWORD_XMM_BROADCAST) {
        source_register_bits = 128u;
    }
    if (shape.form == X86_EVEX_FORM_4VNNIW
        || shape.form == X86_EVEX_FORM_4FMAPS_PACKED
        || shape.form == X86_EVEX_FORM_4FMAPS_SCALAR) {
        memory_bits = 128u;
    } else if (shape.form == X86_EVEX_FORM_MEMORY_BROADCAST_BLOCK) {
        memory_bits = (opcode & UINT8_C(1)) != 0u ? 256u : 128u;
    } else if (shape.form == X86_EVEX_FORM_QWORD_XMM_BROADCAST) {
        memory_bits = 64u;
    } else if (shape.form == X86_EVEX_FORM_EXTRACT_HALF_IMM8) {
        memory_bits = 256u;
    } else if (shape.form == X86_EVEX_FORM_EXTRACT_QUARTER_IMM8) {
        memory_bits = 128u;
    } else if (is_scalar) {
        memory_bits = shape.element_bits;
    } else if (!modrm.is_register && (p2 & UINT8_C(0x10)) != 0) {
        memory_bits = shape.element_bits;
    } else if (shape.form == X86_EVEX_FORM_UNARY_WIDEN) {
        memory_bits = vector_bits / 2u;
    } else {
        memory_bits = vector_bits;
    }
    broadcast_count = shape.form == X86_EVEX_FORM_UNARY_WIDEN
        ? vector_bits / (2u * shape.element_bits)
        : vector_bits / shape.element_bits;

    /* EVEX disp8 is compressed by the selected tuple size. */
    if (!modrm.is_register && modrm.mod == 1) {
        const unsigned int tuple_bits =
            shape.form == X86_EVEX_FORM_COMPRESS
                || shape.form == X86_EVEX_FORM_EXPAND
            ? shape.element_bits : memory_bits;

        modrm.displacement *= (int64_t)(tuple_bits / 8u);
    }
    if (has_imm8
        && shape.form
            != X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
        && shape.form != X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE
        && !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    /* The opcode-71/72/73 imm8 belongs to every extension, including
     * reserved controls, so it is consumed before this exact legality split.
     * 71 allocates /2,/4,/6; 72 has D/Q rotate controls and its documented
     * W split; 73 allocates W=1 /2,/6 qword shifts and WIG /3,/7 DQ
     * lane shifts. */
    if (shape.form
            == X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
        && ((opcode == UINT8_C(0x71)
                && modrm.reg3 != 2u && modrm.reg3 != 4u
                && modrm.reg3 != 6u)
            || (opcode == UINT8_C(0x72)
                && (modrm.reg3 == 3u || modrm.reg3 == 5u
                    || modrm.reg3 == 7u
                    || (w != 0
                        && (modrm.reg3 == 2u || modrm.reg3 == 6u))))
            || (opcode == UINT8_C(0x73)
                && modrm.reg3 != 2u && modrm.reg3 != 3u
                && modrm.reg3 != 6u && modrm.reg3 != 7u))) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    (void)aaa;
    (void)vector_bits;
    (void)destination_bits;
    (void)source_register_bits;
    (void)memory_bits;
    (void)broadcast_count;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    descriptor = find_evex_descriptor(
        map_select, opcode, prefix, w, shape.form, modrm.reg3);
    if (descriptor == NULL
        || descriptor->element_bits != shape.element_bits
        || descriptor->flags != shape.flags) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    decoder->name_id = descriptor->name_id;
    if (descriptor->name_id == CDISASM_X86_NAME_VCOMPRESSPD
        || descriptor->name_id == CDISASM_X86_NAME_VCOMPRESSPS) {
        const cdisasm_x86_form_id base =
            descriptor->name_id == CDISASM_X86_NAME_VCOMPRESSPD
                ? UINT16_C(3637) : UINT16_C(3643);

        /* XED orders the three GSCAT memory forms before the three
         * register forms for floating compress. */
        decoder->form_id = (cdisasm_x86_form_id)(
            base + (modrm.is_register ? 3u : 0u) + ll);
    } else if (descriptor->name_id == CDISASM_X86_NAME_VEXPANDPD
        || descriptor->name_id == CDISASM_X86_NAME_VEXPANDPS) {
        const cdisasm_x86_form_id base =
            descriptor->name_id == CDISASM_X86_NAME_VEXPANDPD
                ? UINT16_C(4527) : UINT16_C(4533);

        /* XED interleaves the memory and register source at each VL for
         * floating expand. */
        decoder->form_id = (cdisasm_x86_form_id)(
            base + 2u * ll + (modrm.is_register ? 1u : 0u));
    } else if (is_owned_map1_vor) {
        const cdisasm_x86_form_id base =
            prefix == X86_SIMD_PREFIX_P66
                ? UINT16_C(6056) : UINT16_C(6066);
        const unsigned int width_offset =
            ll == 0u ? 0u : ll == 1u ? 4u : 6u;

        decoder->form_id = (cdisasm_x86_form_id)(
            base + width_offset + (modrm.is_register ? 1u : 0u));
    } else if (is_owned_map2_vpabs) {
        cdisasm_x86_form_id base;

        if (opcode == UINT8_C(0x1c)) {
            base = UINT16_C(6090);
        } else if (opcode == UINT8_C(0x1d)) {
            base = UINT16_C(6116);
        } else if (opcode == UINT8_C(0x1e)) {
            base = UINT16_C(6100);
        } else {
            base = UINT16_C(6108);
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            base + (opcode == UINT8_C(0x1f)
                    ? 2u * ll : ll == 2u ? 6u : 2u * ll)
                + (modrm.is_register ? 1u : 0u));
    } else if (is_owned_vpack) {
        cdisasm_x86_form_id base;
        unsigned int width_offset;

        if (opcode == UINT8_C(0x6b)) {
            base = UINT16_C(6126);
            width_offset = ll == 2u ? 6u : 2u * ll;
        } else if (opcode == UINT8_C(0x63)) {
            base = UINT16_C(6136);
            width_offset = ll == 2u ? 6u : 2u * ll;
        } else if (map_select == UINT8_C(2)) {
            base = UINT16_C(6146);
            width_offset = ll == 0u ? 0u : ll == 1u ? 4u : 6u;
        } else {
            base = UINT16_C(6156);
            width_offset = ll == 0u ? 0u : ll == 1u ? 4u : 6u;
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            base + width_offset + (modrm.is_register ? 1u : 0u));
    } else if (is_owned_map2_vp2intersect) {
        const cdisasm_x86_form_id base = w != 0
            ? UINT16_C(6080) : UINT16_C(6074);

        decoder->form_id = (cdisasm_x86_form_id)(
            base + 2u * ll + (modrm.is_register ? 1u : 0u));
    } else if (shape.form == X86_EVEX_FORM_PACKED_INTEGER_MINMAX) {
        cdisasm_x86_form_id xmm_memory;
        cdisasm_x86_form_id ymm_memory;
        cdisasm_x86_form_id zmm_memory;

        switch (descriptor->name_id) {
            case CDISASM_X86_NAME_VPMAXSB:
                xmm_memory = UINT16_C(7162);
                ymm_memory = UINT16_C(7164);
                zmm_memory = UINT16_C(7168);
                break;
            case CDISASM_X86_NAME_VPMAXSD:
                xmm_memory = UINT16_C(7172);
                ymm_memory = UINT16_C(7174);
                zmm_memory = UINT16_C(7178);
                break;
            case CDISASM_X86_NAME_VPMAXSQ:
                xmm_memory = UINT16_C(7180);
                ymm_memory = UINT16_C(7182);
                zmm_memory = UINT16_C(7184);
                break;
            case CDISASM_X86_NAME_VPMAXSW:
                xmm_memory = UINT16_C(7188);
                ymm_memory = UINT16_C(7190);
                zmm_memory = UINT16_C(7194);
                break;
            case CDISASM_X86_NAME_VPMAXUB:
                xmm_memory = UINT16_C(7198);
                ymm_memory = UINT16_C(7202);
                zmm_memory = UINT16_C(7204);
                break;
            case CDISASM_X86_NAME_VPMAXUD:
                xmm_memory = UINT16_C(7208);
                ymm_memory = UINT16_C(7212);
                zmm_memory = UINT16_C(7214);
                break;
            case CDISASM_X86_NAME_VPMAXUQ:
                xmm_memory = UINT16_C(7216);
                ymm_memory = UINT16_C(7218);
                zmm_memory = UINT16_C(7220);
                break;
            case CDISASM_X86_NAME_VPMAXUW:
                xmm_memory = UINT16_C(7224);
                ymm_memory = UINT16_C(7228);
                zmm_memory = UINT16_C(7230);
                break;
            case CDISASM_X86_NAME_VPMINSB:
                xmm_memory = UINT16_C(7234);
                ymm_memory = UINT16_C(7236);
                zmm_memory = UINT16_C(7240);
                break;
            case CDISASM_X86_NAME_VPMINSD:
                xmm_memory = UINT16_C(7244);
                ymm_memory = UINT16_C(7246);
                zmm_memory = UINT16_C(7250);
                break;
            case CDISASM_X86_NAME_VPMINSQ:
                xmm_memory = UINT16_C(7252);
                ymm_memory = UINT16_C(7254);
                zmm_memory = UINT16_C(7256);
                break;
            case CDISASM_X86_NAME_VPMINSW:
                xmm_memory = UINT16_C(7260);
                ymm_memory = UINT16_C(7262);
                zmm_memory = UINT16_C(7266);
                break;
            case CDISASM_X86_NAME_VPMINUB:
                xmm_memory = UINT16_C(7270);
                ymm_memory = UINT16_C(7274);
                zmm_memory = UINT16_C(7276);
                break;
            case CDISASM_X86_NAME_VPMINUD:
                xmm_memory = UINT16_C(7280);
                ymm_memory = UINT16_C(7284);
                zmm_memory = UINT16_C(7286);
                break;
            case CDISASM_X86_NAME_VPMINUQ:
                xmm_memory = UINT16_C(7288);
                ymm_memory = UINT16_C(7290);
                zmm_memory = UINT16_C(7292);
                break;
            case CDISASM_X86_NAME_VPMINUW:
                xmm_memory = UINT16_C(7296);
                ymm_memory = UINT16_C(7300);
                zmm_memory = UINT16_C(7302);
                break;
            default:
                return decoder_fail(
                    decoder, CDISASM_STATUS_INTERNAL_ERROR);
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            (ll == 0u ? xmm_memory : ll == 1u ? ymm_memory : zmm_memory)
            + (modrm.is_register ? 1u : 0u));
    } else if (is_owned_map1_vmul) {
        /* Preserve the exact pinned XED identity before effective groups
         * are materialized.  Register EVEX.b selects embedded rounding but
         * keeps the packed ZMM or scalar register form identity. */
        if (prefix == X86_SIMD_PREFIX_P66) {
            decoder->form_id = (cdisasm_x86_form_id)(
                modrm.is_register && (p2 & UINT8_C(0x10)) != 0
                    ? UINT16_C(6021)
                    : UINT16_C(6014) + (ll == 2u ? 6u : 2u * ll)
                        + (modrm.is_register ? 1u : 0u));
        } else if (prefix == X86_SIMD_PREFIX_NONE) {
            decoder->form_id = (cdisasm_x86_form_id)(
                modrm.is_register && (p2 & UINT8_C(0x10)) != 0
                    ? UINT16_C(6037)
                    : UINT16_C(6030) + (ll == 2u ? 6u : 2u * ll)
                        + (modrm.is_register ? 1u : 0u));
        } else if (prefix == X86_SIMD_PREFIX_PF2) {
            decoder->form_id = (cdisasm_x86_form_id)(
                UINT16_C(6040) + (modrm.is_register ? 1u : 0u));
        } else {
            decoder->form_id = (cdisasm_x86_form_id)(
                UINT16_C(6046) + (modrm.is_register ? 1u : 0u));
        }
    } else if (is_apx_map5_vmul) {
        /* Preserve the exact pinned XED identity before effective groups are
         * materialized.  The generic identity attachment runs later and is
         * therefore too late to publish the width-specific ISA_SET here. */
        if (prefix == X86_SIMD_PREFIX_NONE) {
            decoder->form_id = (cdisasm_x86_form_id)(
                modrm.is_register && (p2 & UINT8_C(0x10)) != 0
                    ? UINT16_C(6027)
                    : UINT16_C(6022) + 2u * ll
                        + (modrm.is_register ? 1u : 0u));
        } else if (prefix == X86_SIMD_PREFIX_P66) {
            decoder->form_id = (cdisasm_x86_form_id)(
                UINT16_C(6006) + 2u * ll
                + (modrm.is_register ? 1u : 0u));
        } else {
            decoder->form_id = (cdisasm_x86_form_id)(
                UINT16_C(6042) + (modrm.is_register ? 1u : 0u));
        }
    } else if (descriptor->name_id
            == CDISASM_X86_NAME_VCVTNEPS2BF16) {
        /* XED orders the two narrow memory forms first, followed by their
         * register counterparts, and places VL512 after the VEX forms. */
        if (ll == 0u) {
            decoder->form_id = (cdisasm_x86_form_id)(
                modrm.is_register ? UINT16_C(3835) : UINT16_C(3833));
        } else if (ll == 1u) {
            decoder->form_id = (cdisasm_x86_form_id)(
                modrm.is_register ? UINT16_C(3836) : UINT16_C(3834));
        } else {
            decoder->form_id = (cdisasm_x86_form_id)(
                modrm.is_register ? UINT16_C(3842) : UINT16_C(3841));
        }
    } else if (descriptor->form
            == X86_EVEX_FORM_MEMORY_BROADCAST_BLOCK) {
        switch (descriptor->name_id) {
            case CDISASM_X86_NAME_VBROADCASTF32X4:
                decoder->form_id = (cdisasm_x86_form_id)(
                    ll == 1u ? UINT16_C(3548) : UINT16_C(3549));
                break;
            case CDISASM_X86_NAME_VBROADCASTF32X8:
                decoder->form_id = UINT16_C(3550);
                break;
            case CDISASM_X86_NAME_VBROADCASTF64X2:
                decoder->form_id = (cdisasm_x86_form_id)(
                    ll == 1u ? UINT16_C(3551) : UINT16_C(3552));
                break;
            case CDISASM_X86_NAME_VBROADCASTF64X4:
                decoder->form_id = UINT16_C(3553);
                break;
            case CDISASM_X86_NAME_VBROADCASTI32X4:
                decoder->form_id = (cdisasm_x86_form_id)(
                    ll == 1u ? UINT16_C(3561) : UINT16_C(3562));
                break;
            case CDISASM_X86_NAME_VBROADCASTI32X8:
                decoder->form_id = UINT16_C(3563);
                break;
            case CDISASM_X86_NAME_VBROADCASTI64X2:
                decoder->form_id = (cdisasm_x86_form_id)(
                    ll == 1u ? UINT16_C(3564) : UINT16_C(3565));
                break;
            case CDISASM_X86_NAME_VBROADCASTI64X4:
                decoder->form_id = UINT16_C(3566);
                break;
            default:
                return decoder_fail(
                    decoder, CDISASM_STATUS_INTERNAL_ERROR);
        }
    } else if (descriptor->form
            == X86_EVEX_FORM_QWORD_XMM_BROADCAST) {
        const cdisasm_x86_form_id base = descriptor->name_id
                == CDISASM_X86_NAME_VBROADCASTF32X2
            ? UINT16_C(3544) : UINT16_C(3555);
        const unsigned int first_ll = descriptor->name_id
                == CDISASM_X86_NAME_VBROADCASTF32X2
            ? 1u : 0u;

        decoder->form_id = (cdisasm_x86_form_id)(
            base + 2u * (ll - first_ll)
                + (modrm.is_register ? 1u : 0u));
    } else if (descriptor->form == X86_EVEX_FORM_EXTRACT_HALF_IMM8) {
        cdisasm_x86_form_id base;

        switch (descriptor->name_id) {
            case CDISASM_X86_NAME_VEXTRACTF32X8:
                base = UINT16_C(4545);
                break;
            case CDISASM_X86_NAME_VEXTRACTF64X4:
                base = UINT16_C(4551);
                break;
            case CDISASM_X86_NAME_VEXTRACTI32X8:
                base = UINT16_C(4559);
                break;
            case CDISASM_X86_NAME_VEXTRACTI64X4:
                base = UINT16_C(4565);
                break;
            default:
                return decoder_fail(
                    decoder, CDISASM_STATUS_INTERNAL_ERROR);
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            base + (modrm.is_register ? 1u : 0u));
    } else if (descriptor->form == X86_EVEX_FORM_EXTRACT_QUARTER_IMM8) {
        cdisasm_x86_form_id base;

        switch (descriptor->name_id) {
            case CDISASM_X86_NAME_VEXTRACTF32X4:
                base = UINT16_C(4541);
                break;
            case CDISASM_X86_NAME_VEXTRACTF64X2:
                base = UINT16_C(4547);
                break;
            case CDISASM_X86_NAME_VEXTRACTI32X4:
                base = UINT16_C(4555);
                break;
            case CDISASM_X86_NAME_VEXTRACTI64X2:
                base = UINT16_C(4561);
                break;
            default:
                return decoder_fail(
                    decoder, CDISASM_STATUS_INTERNAL_ERROR);
        }
        decoder->form_id = (cdisasm_x86_form_id)(
            base + (modrm.is_register ? 2u : 0u) + (ll - 1u));
    }
    decoder_require_caps(decoder, X86_CAP_AVX);
    if ((p0 & UINT8_C(0x08)) != 0 || apx_u0) {
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    /* AVX512F_SCALAR uses XMM operands without an AVX512VL prerequisite. */
    if ((descriptor->flags & X86_EVEX_FLAG_AVX10_2) != 0) {
        /* These AVX10.2 allocations have no AVX-512 alternate route.  Their
         * descriptor feature, when independent, is added below; every form
         * first requires the AVX10.2 encoding foundation recorded here. */
        decoder_require_extra(decoder, CDISASM_X86_GROUP_AVX10_2);
    } else if (descriptor->feature_group
            == CDISASM_X86_GROUP_AVX512FP16) {
        decoder_require_evex_fp16_foundation(
            decoder, !is_scalar && vector_bits < 512u);
    } else if (descriptor->form == X86_EVEX_FORM_4VNNIW
        || descriptor->form == X86_EVEX_FORM_4FMAPS_PACKED
        || descriptor->form == X86_EVEX_FORM_4FMAPS_SCALAR) {
        decoder_require_evex_foundation(decoder, 0, 0);
        decoder_require_extra(decoder, descriptor->feature_group);
    } else if (is_owned_map1_vor
        || is_owned_map2_vpabs
        || is_owned_vpack
        || descriptor->form == X86_EVEX_FORM_COMPARE_MASK_IMM8
        || descriptor->form == X86_EVEX_FORM_PACKED_INTEGER_MINMAX
        || descriptor->form == X86_EVEX_FORM_PACKED_INTEGER_MULTIPLY
        || descriptor->form == X86_EVEX_FORM_PACKED_INTEGER_ADD_SUB
        || descriptor->form == X86_EVEX_FORM_PACKED_INTEGER_LOGICAL
        || descriptor->form == X86_EVEX_FORM_PACKED_INTEGER_AVERAGE
        || descriptor->form
            == X86_EVEX_FORM_PACKED_INTEGER_VARIABLE_SHIFT
        || descriptor->form
            == X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
        || descriptor->form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE
        || descriptor->form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
        || descriptor->form == X86_EVEX_FORM_COMPRESS
        || descriptor->form == X86_EVEX_FORM_EXPAND
        || descriptor->form == X86_EVEX_FORM_POPCOUNT
        || descriptor->form == X86_EVEX_FORM_BITALG_MASK_DESTINATION
        || descriptor->form == X86_EVEX_FORM_MASK_BROADCAST
        || descriptor->form == X86_EVEX_FORM_VNNI_DOT_PRODUCT
        || descriptor->form == X86_EVEX_FORM_PERMUTE_TERNARY) {
        decoder_require_evex_packed_integer_foundation(
            decoder, descriptor->feature_group,
            vector_bits < 512u);
    } else {
        decoder_require_evex_foundation(
            decoder,
            !is_scalar && vector_bits < 512u,
            (descriptor->flags & X86_EVEX_FLAG_AVX10) != 0);
    }
    /* An AVX10 encoding route replaces the EVEX foundation, not the
     * instruction's independent functional feature bit. */
    if (!is_owned_map1_vor
        && !is_owned_map2_vpabs
        && !is_owned_vpack
        && descriptor->form != X86_EVEX_FORM_COMPARE_MASK_IMM8
        && descriptor->form != X86_EVEX_FORM_PACKED_INTEGER_MINMAX
        && descriptor->form != X86_EVEX_FORM_PACKED_INTEGER_MULTIPLY
        && descriptor->form != X86_EVEX_FORM_PACKED_INTEGER_ADD_SUB
        && descriptor->form != X86_EVEX_FORM_PACKED_INTEGER_LOGICAL
        && descriptor->form != X86_EVEX_FORM_PACKED_INTEGER_AVERAGE
        && descriptor->form
            != X86_EVEX_FORM_PACKED_INTEGER_VARIABLE_SHIFT
        && descriptor->form
            != X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE
        && descriptor->form != X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE
        && descriptor->form != X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
        && descriptor->form != X86_EVEX_FORM_COMPRESS
        && descriptor->form != X86_EVEX_FORM_EXPAND
        && descriptor->form != X86_EVEX_FORM_POPCOUNT
        && descriptor->form != X86_EVEX_FORM_BITALG_MASK_DESTINATION
        && descriptor->form != X86_EVEX_FORM_MASK_BROADCAST
        && descriptor->form != X86_EVEX_FORM_VNNI_DOT_PRODUCT
        && descriptor->form != X86_EVEX_FORM_PERMUTE_TERNARY
        && descriptor->feature_group != CDISASM_X86_GROUP_AVX512F
        && descriptor->feature_group
            != CDISASM_X86_GROUP_AVX512FP16) {
        decoder_require_extra(decoder, descriptor->feature_group);
    }
    if (aaa != 0) {
        decoder->mask_reg = (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa);
        decoder->mask_mode = (p2 & UINT8_C(0x80)) != 0
            ? CDISASM_X86_MASK_ZERO
            : CDISASM_X86_MASK_MERGE;
    }
    if (modrm.is_register && (p2 & UINT8_C(0x10)) != 0) {
        if ((descriptor->flags & X86_EVEX_FLAG_ROUND) != 0) {
            decoder->rounding = (cdisasm_x86_rounding_mode)(ll + 1u);
            decoder->sae = CDISASM_X86_SAE_ENABLED;
        } else if ((descriptor->flags & X86_EVEX_FLAG_SAE) != 0) {
            decoder->sae = CDISASM_X86_SAE_ENABLED;
        }
    }

    destination_access = (descriptor->feature_group == CDISASM_X86_GROUP_FMA3
            || descriptor->form == X86_EVEX_FORM_4VNNIW
            || descriptor->form == X86_EVEX_FORM_4FMAPS_PACKED
            || descriptor->form == X86_EVEX_FORM_4FMAPS_SCALAR
            || descriptor->form == X86_EVEX_FORM_VNNI_DOT_PRODUCT
            || descriptor->name_id == CDISASM_X86_NAME_VPMADD52LUQ
            || descriptor->name_id == CDISASM_X86_NAME_VPMADD52HUQ
            || descriptor->form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
            || descriptor->name_id == CDISASM_X86_NAME_VPERMI2B
            || descriptor->name_id == CDISASM_X86_NAME_VPERMT2B
            || descriptor->name_id == CDISASM_X86_NAME_VPERMI2W
            || descriptor->name_id == CDISASM_X86_NAME_VPERMT2W
            || decoder->mask_mode == CDISASM_X86_MASK_MERGE)
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE;
    if (descriptor->form == X86_EVEX_FORM_COMPARE_MASK_IMM8) {
        const unsigned int mask_bits =
            vector_bits / descriptor->element_bits;

        if (!add_mask_register_operand_access(
                decoder, modrm.reg3, mask_bits,
                aaa != 0 ? CDISASM_OPERAND_ACCESS_READ_WRITE
                         : CDISASM_OPERAND_ACCESS_WRITE)
            || !add_vector_register_operand_access(
                decoder, source_index, source_register_bits,
                CDISASM_OPERAND_ACCESS_READ)
            || !add_vector_rm_operand_access(
                decoder, &modrm, source_register_bits, memory_bits,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
        if (!modrm.is_register && (p2 & UINT8_C(0x10)) != 0) {
            decoder->operand[decoder->operand_count - 1].broadcast =
                (cdisasm_x86_broadcast)broadcast_count;
        }
        return add_immediate_value(decoder, 8u, immediate, 0);
    }
    if (descriptor->form == X86_EVEX_FORM_BITALG_MASK_DESTINATION) {
        const unsigned int mask_bits = vector_bits / 8u;

        return add_mask_register_operand_access(
                decoder, modrm.reg3, mask_bits,
                aaa != 0 ? CDISASM_OPERAND_ACCESS_READ_WRITE
                         : CDISASM_OPERAND_ACCESS_WRITE)
            && add_vector_register_operand_access(
                decoder, source_index, source_register_bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_vector_rm_operand_access(
                decoder, &modrm, source_register_bits, memory_bits,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (descriptor->form == X86_EVEX_FORM_MULTIDEST2) {
        const unsigned int mask_bits =
            vector_bits / descriptor->element_bits;
        const unsigned int mask_pair = modrm.reg & ~1u;

        if (!add_mask_register_operand_access(
                decoder, mask_pair, mask_bits,
                CDISASM_OPERAND_ACCESS_WRITE)
            || !add_mask_register_operand_access(
                decoder, mask_pair + 1u, mask_bits,
                CDISASM_OPERAND_ACCESS_WRITE)) {
            return 0;
        }
        decoder->operand[decoder->operand_count - 1].flags |=
            CDISASM_OPERAND_FLAG_IMPLICIT;
        if (!add_vector_register_operand_access(
                decoder, source_index, source_register_bits,
                CDISASM_OPERAND_ACCESS_READ)
            || !add_vector_rm_operand_access(
                decoder, &modrm, source_register_bits, memory_bits,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
        if (!modrm.is_register && (p2 & UINT8_C(0x10)) != 0) {
            decoder->operand[decoder->operand_count - 1].broadcast =
                (cdisasm_x86_broadcast)broadcast_count;
        }
        return 1;
    }
    if (descriptor->form == X86_EVEX_FORM_MASK_BROADCAST) {
        return add_vector_register_operand_access(
                decoder, modrm.reg, destination_bits,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_mask_register_operand_access(
                decoder, modrm.rm3, 64u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (descriptor->form
        == X86_EVEX_FORM_PACKED_INTEGER_IMMEDIATE_SHIFT_ROTATE) {
        if (!add_vector_register_operand_access(
                decoder, source_index, destination_bits,
                destination_access)
            || !add_vector_rm_operand_access(
                decoder, &modrm, source_register_bits, memory_bits,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
        if (!modrm.is_register && (p2 & UINT8_C(0x10)) != 0) {
            decoder->operand[decoder->operand_count - 1].broadcast =
                (cdisasm_x86_broadcast)broadcast_count;
        }
        return add_immediate_value(decoder, 8u, immediate, 0);
    }
    if (descriptor->form == X86_EVEX_FORM_COMPRESS) {
        if (!add_vector_rm_operand_access(
                decoder, &modrm, destination_bits, memory_bits,
                modrm.is_register ? destination_access
                                  : CDISASM_OPERAND_ACCESS_WRITE)
            || !add_vector_register_operand_access(
                decoder, modrm.reg, source_register_bits,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
        return 1;
    }
    if (descriptor->form == X86_EVEX_FORM_EXPAND) {
        return add_vector_register_operand_access(
                decoder, modrm.reg, destination_bits, destination_access)
            && add_vector_rm_operand_access(
                decoder, &modrm, source_register_bits, memory_bits,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (descriptor->form == X86_EVEX_FORM_EXTRACT_HALF_IMM8) {
        return add_vector_rm_operand_access(
                   decoder, &modrm, 256u, 256u,
                   destination_access)
            && add_vector_register_operand_access(
                decoder, modrm.reg, 512u,
                CDISASM_OPERAND_ACCESS_READ)
            && add_immediate_value(decoder, 8u, immediate, 0);
    }
    if (descriptor->form == X86_EVEX_FORM_EXTRACT_QUARTER_IMM8) {
        return add_vector_rm_operand_access(
                   decoder, &modrm, 128u, 128u,
                   destination_access)
            && add_vector_register_operand_access(
                decoder, modrm.reg, vector_bits,
                CDISASM_OPERAND_ACCESS_READ)
            && add_immediate_value(decoder, 8u, immediate, 0);
    }
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, destination_bits, destination_access)) {
        return 0;
    }
    if ((descriptor->form == X86_EVEX_FORM_NDS_VECTOR
            || descriptor->form == X86_EVEX_FORM_NDS_VECTOR_IMM8
            || descriptor->form == X86_EVEX_FORM_NDS_SCALAR
            || descriptor->form
                == X86_EVEX_FORM_PACKED_INTEGER_MINMAX
            || descriptor->form
                == X86_EVEX_FORM_PACKED_INTEGER_MULTIPLY
            || descriptor->form
                == X86_EVEX_FORM_PACKED_INTEGER_ADD_SUB
            || descriptor->form
                == X86_EVEX_FORM_PACKED_INTEGER_LOGICAL
            || descriptor->form
                == X86_EVEX_FORM_PACKED_INTEGER_AVERAGE
            || descriptor->form
                == X86_EVEX_FORM_PACKED_INTEGER_VARIABLE_SHIFT
            || descriptor->form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_IMMEDIATE
            || descriptor->form == X86_EVEX_FORM_VBMI2_DOUBLE_SHIFT_VARIABLE
            || descriptor->form == X86_EVEX_FORM_VNNI_DOT_PRODUCT
            || descriptor->form == X86_EVEX_FORM_4VNNIW
            || descriptor->form == X86_EVEX_FORM_4FMAPS_PACKED
            || descriptor->form == X86_EVEX_FORM_4FMAPS_SCALAR
            || descriptor->form == X86_EVEX_FORM_PERMUTE_TERNARY)
        && !add_vector_register_operand_access(
            decoder, source_index, source_register_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (!add_vector_rm_operand_access(
            decoder, &modrm, source_register_bits, memory_bits,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (!modrm.is_register && (p2 & UINT8_C(0x10)) != 0) {
        decoder->operand[decoder->operand_count - 1].broadcast =
            (cdisasm_x86_broadcast)broadcast_count;
    }
    return !has_imm8 || add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static const x86_rex2_descriptor *find_rex2_map0_descriptor(uint8_t opcode)
{
    size_t index;

    for (index = 0;
         index < sizeof(x86_rex2_map0) / sizeof(x86_rex2_map0[0]);
         ++index) {
        if (x86_rex2_map0[index].opcode == opcode) {
            return &x86_rex2_map0[index];
        }
    }
    return NULL;
}

static int decode_system_0fae(x86_decoder *decoder);
static int decode_movnti(x86_decoder *decoder);
static int decode_lddqu_legacy(x86_decoder *decoder, uint8_t opcode);
static int decode_non_temporal_simd_store(
    x86_decoder *decoder,
    uint8_t opcode);
static int decode_vmx_read_write(x86_decoder *decoder, uint8_t opcode);
static int decode_vmx_pointer(x86_decoder *decoder);
static int decode_legacy_simd_map(
    x86_decoder *decoder,
    const x86_simd_descriptor *map,
    size_t count,
    uint8_t opcode);
static int decode_cet_group7(
    x86_decoder *decoder,
    const x86_modrm *modrm);
static int decode_fixed_virtualization_system(
    x86_decoder *decoder,
    const x86_modrm *modrm);
static int decode_cldemote_nop_row(x86_decoder *decoder);
static int decode_prefetch_row(x86_decoder *decoder);
static int decode_3dnow_prefetch(x86_decoder *decoder);

static int rex2_opcode_is_reserved(uint8_t map, uint8_t opcode)
{
    if (map == 0) {
        const uint8_t row = opcode & UINT8_C(0xf0);

        if (opcode == UINT8_C(0x0f)
            || opcode == UINT8_C(0x26)
            || opcode == UINT8_C(0x2e)
            || opcode == UINT8_C(0x36)
            || opcode == UINT8_C(0x3e)
            || opcode == UINT8_C(0x62)
            || (opcode >= UINT8_C(0x64) && opcode <= UINT8_C(0x67))
            || opcode == UINT8_C(0xc4)
            || opcode == UINT8_C(0xc5)
            || opcode == UINT8_C(0xd5)
            || opcode == UINT8_C(0xf0)
            || opcode == UINT8_C(0xf2)
            || opcode == UINT8_C(0xf3)) {
            return 1;
        }
        return row == UINT8_C(0x40)
            || row == UINT8_C(0x70)
            || (row == UINT8_C(0xa0) && opcode != UINT8_C(0xa1))
            || row == UINT8_C(0xe0);
    }
    return (opcode & UINT8_C(0xf0)) == UINT8_C(0x30)
        || (opcode & UINT8_C(0xf0)) == UINT8_C(0x80);
}

static int decode_rex2_primary(x86_decoder *decoder, uint8_t opcode)
{
    const x86_rex2_descriptor *descriptor;
    x86_modrm modrm;
    int result;

    if (decoder->mode != CDISASM_MODE_64) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (rex2_opcode_is_reserved(decoder->rex2_map, opcode)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (decoder->rex2_map == 1 && opcode == UINT8_C(0x1c)) {
        return decode_cldemote_nop_row(decoder);
    }
    if (decoder->rex2_map == 1 && opcode == UINT8_C(0x18)) {
        return decode_prefetch_row(decoder);
    }
    if (decoder->rex2_map == 1 && opcode == UINT8_C(0x0d)) {
        return decode_3dnow_prefetch(decoder);
    }
    if (decoder->rex2_map == 1 && opcode == UINT8_C(0xc7)) {
        result = decode_vmx_pointer(decoder);
#if USE_EXTRA_OPCODES
        if (result) {
            decoder_require_caps(decoder, X86_CAP_AMD64);
            decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        }
#endif
        return result;
    }
    if (decoder->rex2_map == 1
        && (opcode == UINT8_C(0x78) || opcode == UINT8_C(0x79))) {
        /* Mandatory 66/F2 retain the SSE4a EXTRQ/INSERTQ collisions under
         * APX map 1.  REX2.R4/B4 do not extend legacy XMM operands, while
         * the ordinary R/B bits still select XMM8--XMM15. */
        if (decoder->operand_override || decoder->repeat_prefix != 0) {
            const uint8_t saved_reg_high = decoder->modrm_reg_high;
            const uint8_t saved_rm_high = decoder->modrm_rm_high;

            decoder->modrm_reg_high = 0;
            decoder->modrm_rm_high = 0;
            result = decode_legacy_simd_map(
                decoder,
                x86_0f_simd_map,
                sizeof(x86_0f_simd_map) / sizeof(x86_0f_simd_map[0]),
                opcode);
            decoder->modrm_reg_high = saved_reg_high;
            decoder->modrm_rm_high = saved_rm_high;
            if (result < 0) {
                /* Preserve the NP VMX row's complete-EA ownership so a
                 * reserved F3 spelling still reports truncation before the
                 * mandatory-prefix error. */
                return decode_vmx_read_write(decoder, opcode);
            }
#if USE_EXTRA_OPCODES
            if (result) {
                decoder_require_caps(decoder, X86_CAP_AMD64);
                decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
            }
#endif
            return result;
        }
        result = decode_vmx_read_write(decoder, opcode);
#if USE_EXTRA_OPCODES
        if (result) {
            decoder_require_caps(decoder, X86_CAP_AMD64);
            decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        }
#endif
        return result;
    }
    if (decoder->rex2_map == 1 && opcode == UINT8_C(0x01)) {
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        result = decode_cet_group7(decoder, &modrm);
        if (result >= 0) {
#if USE_EXTRA_OPCODES
            if (result) {
                decoder_require_caps(decoder, X86_CAP_AMD64);
                decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
            }
#endif
            return result;
        }
        if (decoder->encoding.modrm != UINT8_C(0xc3)
            && decoder->encoding.modrm != UINT8_C(0xc4)
            && decoder->encoding.modrm != UINT8_C(0xc5)
            && decoder->encoding.modrm != UINT8_C(0xc6)
            && decoder->encoding.modrm != UINT8_C(0xc7)
            && decoder->encoding.modrm != UINT8_C(0xc8)
            && decoder->encoding.modrm != UINT8_C(0xc9)
            && decoder->encoding.modrm != UINT8_C(0xca)
            && decoder->encoding.modrm != UINT8_C(0xcb)
            && decoder->encoding.modrm != UINT8_C(0xd8)
            && decoder->encoding.modrm != UINT8_C(0xdb)
            && decoder->encoding.modrm != UINT8_C(0xe8)
            && decoder->encoding.modrm != UINT8_C(0xfa)
            && decoder->encoding.modrm != UINT8_C(0xfb)
            && decoder->encoding.modrm != UINT8_C(0xfc)
            && decoder->encoding.modrm != UINT8_C(0xfd)
            && decoder->encoding.modrm != UINT8_C(0xfe)
            && decoder->encoding.modrm != UINT8_C(0xff)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        result = decode_fixed_virtualization_system(decoder, &modrm);
#if USE_EXTRA_OPCODES
        if (result) {
            decoder_require_caps(decoder, X86_CAP_AMD64);
            decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        }
#endif
        return result;
    }
    if (decoder->rex2_map == 1 && opcode == UINT8_C(0x09)) {
        if (decoder->lock_prefix) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        decoder->name_id = CDISASM_X86_NAME_WBINVD;
        decoder_require_caps(decoder, X86_CAP_80486);
        return 1;
#endif
    }
    if (decoder->rex2_map == 1 && opcode == UINT8_C(0xae)) {
        /* APX promotes the WAITPKG register forms through REX2 map 1.  The
         * ordinary 0F AE structural decoder still owns mandatory-prefix
         * selection and the CET collisions in this row. */
        result = decode_system_0fae(decoder);
#if USE_EXTRA_OPCODES
        if (result) {
            decoder_require_caps(decoder, X86_CAP_AMD64);
            decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        }
#endif
        return result;
    }
    if (decoder->rex2_map == 1
        && (opcode == UINT8_C(0x2b) || opcode == UINT8_C(0xe7))) {
        /* APX promotes the two legacy non-temporal SIMD-store rows through
         * REX2 map 1.  R4 is ignored for their XMM/MMX source field, while
         * B4/X4 remain available to the effective-address decoder. */
        result = decode_non_temporal_simd_store(decoder, opcode);
#if USE_EXTRA_OPCODES
        if (result) {
            decoder_require_caps(decoder, X86_CAP_AMD64);
            decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        }
#endif
        return result;
    }
    if (decoder->rex2_map == 1 && opcode == UINT8_C(0xf0)) {
        /* REX2 map 1 replaces the 0F escape for legacy LDDQU.  R4 is
         * ignored for the XMM destination; R/X still select XMM0--15 and
         * X4/B4 remain available to the effective-address decoder. */
        result = decode_lddqu_legacy(decoder, opcode);
#if USE_EXTRA_OPCODES
        if (result) {
            decoder_require_caps(decoder, X86_CAP_AMD64);
            decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        }
#endif
        return result;
    }
    if (decoder->rex2_map == 1 && opcode == UINT8_C(0xc3)) {
        /* REX2 map 1 replaces the legacy 0F escape.  MOVNTI otherwise keeps
         * the ordinary row's width and ModRM rules; the wrapper adds the
         * independent APX-F encoding requirement after structural decode. */
        result = decode_movnti(decoder);
#if USE_EXTRA_OPCODES
        if (result) {
            decoder_require_caps(decoder, X86_CAP_AMD64);
            decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        }
#endif
        return result;
    }
    if (decoder->rex2_map != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    if (opcode == UINT8_C(0xa1)) {
        uint64_t target;

        if ((decoder->rex & UINT8_C(0x08)) != 0
            || decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override || decoder->address_override) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!read_immediate_value(decoder, 64u, &target)) {
            return 0;
        }
#if !USE_EXTRA_OPCODES
        (void)target;
        return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_JMPABS;
        decoder->groups |= CDISASM_GROUP_JUMP;
        decoder->branch_target = target;
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
        return add_immediate_value(decoder, 64u, target, 0);
#endif
    }
    descriptor = find_rex2_map0_descriptor(opcode);
    if (descriptor == NULL) {
        return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if ((descriptor->flags & X86_REX2_FLAG_LOCKABLE) != 0
        && descriptor->form == X86_REX2_FORM_RM_REG
        && !modrm.is_register) {
        decoder->lock_allowed = 1;
    }
    if (decoder->lock_prefix && !decoder->lock_allowed) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    const unsigned int bits =
        (descriptor->flags & X86_REX2_FLAG_BYTE) != 0
            ? 8u
            : decoder->operand_bits;
    const cdisasm_operand_access destination_access =
        (cdisasm_operand_access)descriptor->destination_access;

    decoder->name_id = descriptor->name_id;
    decoder_require_caps(decoder, X86_CAP_AMD64);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    if (descriptor->form == X86_REX2_FORM_RM_REG) {
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(decoder, destination_access)
            && add_register_operand_access(
                decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ);
    }
    return add_register_operand_access(
            decoder, modrm.reg, bits, destination_access)
        && add_rm_operand(decoder, &modrm, bits, 1)
        && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_primary(x86_decoder *decoder, uint8_t opcode)
{
    const x86_opcode_descriptor *descriptor = &x86_primary_map[opcode];
    unsigned int bits;

    if (decoder->rex2_present) {
        return decode_rex2_primary(decoder, opcode);
    }
    if (opcode == UINT8_C(0x62)) {
        return decode_evex(decoder);
    }

    /*
     * The map describes structural decoding only.  CPU availability is
     * accumulated by the handlers and mnemonic_required_caps(), then checked
     * once in decode_core() after the complete instruction is known.
     */
    decoder->groups |= descriptor->groups;

    switch ((x86_decode_form)descriptor->form) {
        case X86_DECODE_FORM_INVALID:
        case X86_DECODE_FORM_PREFIX:
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        case X86_DECODE_FORM_UNSUPPORTED:
            return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        case X86_DECODE_FORM_VEX2:
            return decode_vex2(decoder);
        case X86_DECODE_FORM_VEX3:
            return decode_vex3(decoder);
        case X86_DECODE_FORM_X87:
            return decode_x87(decoder, opcode);
        case X86_DECODE_FORM_FIXED:
            if (descriptor->name_id == CDISASM_X86_NAME_NONE) {
                return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
            }
            decoder->name_id = descriptor->name_id;
            return 1;
        case X86_DECODE_FORM_ALU:
            return decode_alu(decoder, opcode);
        case X86_DECODE_FORM_SEGMENT_STACK:
            if (decoder->mode == CDISASM_MODE_64) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            return add_segment_register_operand(decoder, descriptor->argument);
        case X86_DECODE_FORM_ASCII_ADJUST:
            if (decoder->mode == CDISASM_MODE_64) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            return 1;
        case X86_DECODE_FORM_INC_DEC_REGISTER:
            if (decoder->mode == CDISASM_MODE_64) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return decode_inc_dec_register(decoder, opcode);
        case X86_DECODE_FORM_PUSH_POP_REGISTER:
            return decode_push_pop_register(decoder, opcode);
        case X86_DECODE_FORM_PUSHA_POPA:
            if (decoder->mode == CDISASM_MODE_64) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->argument == 0
                ? (decoder->operand_bits == 16
                    ? CDISASM_X86_NAME_PUSHA
                    : CDISASM_X86_NAME_PUSHAD)
                : (decoder->operand_bits == 16
                    ? CDISASM_X86_NAME_POPA
                    : CDISASM_X86_NAME_POPAD);
            return 1;
        case X86_DECODE_FORM_ARPL_MOVSXD: {
            x86_modrm modrm;

            if (!decode_modrm(decoder, &modrm)) {
                return 0;
            }
            if (decoder->mode == CDISASM_MODE_64) {
                decoder->name_id = CDISASM_X86_NAME_MOVSXD;
                return add_register_operand(
                        decoder,
                        modrm.reg,
                        decoder->operand_bits)
                    && add_rm_operand(
                        decoder,
                        &modrm,
                        decoder->operand_bits == 64
                            ? 32u
                            : decoder->operand_bits,
                        1);
            }
            decoder->name_id = CDISASM_X86_NAME_ARPL;
            return add_rm_operand(decoder, &modrm, 16, 1)
                && add_register_operand(decoder, modrm.reg, 16);
        }
        case X86_DECODE_FORM_PUSH_IMMEDIATE:
            bits = decoder->mode == CDISASM_MODE_64
                ? (decoder->operand_override ? 16u : 64u)
                : decoder->operand_bits;
            decoder->name_id = descriptor->name_id;
            decoder_require_caps(decoder, X86_CAP_80186);
            return descriptor->argument == 8
                ? add_immediate_operand(decoder, 8, 1)
                : add_immediate_operand(
                    decoder,
                    bits == 64 ? 32u : bits,
                    bits == 64);
        case X86_DECODE_FORM_IMUL_IMMEDIATE:
            return decode_imul_immediate(decoder, opcode);
        case X86_DECODE_FORM_STRING_IO:
            return decode_string_io(decoder, opcode);
        case X86_DECODE_FORM_JCC_SHORT:
            return decode_jcc(decoder, descriptor->argument, 8);
        case X86_DECODE_FORM_GROUP1:
            if (opcode == 0x82 && decoder->mode == CDISASM_MODE_64) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return decode_group1(decoder, opcode);
        case X86_DECODE_FORM_BINARY_RM_REG:
            bits = descriptor->argument == 0
                ? decoder->operand_bits
                : descriptor->argument;
            return decode_binary_rm_reg(
                decoder,
                descriptor->name_id,
                bits,
                descriptor->name_id == CDISASM_X86_NAME_MOV && opcode >= 0x8a,
                descriptor->name_id == CDISASM_X86_NAME_XCHG);
        case X86_DECODE_FORM_SEGMENT_MOVE: {
            x86_modrm modrm;

            if (!decode_modrm(decoder, &modrm)) {
                return 0;
            }
            if (modrm.reg3 > 5
                || (descriptor->argument != 0 && modrm.reg3 == 1)) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            if (modrm.reg3 >= 4) {
                decoder_require_caps(decoder, X86_CAP_80386);
            }
            decoder->name_id = descriptor->name_id;
            bits = modrm.is_register ? decoder->operand_bits : 16u;
            return descriptor->argument == 0
                ? (add_rm_operand(decoder, &modrm, bits, 1)
                    && add_segment_register_operand(decoder, modrm.reg3))
                : (add_segment_register_operand(decoder, modrm.reg3)
                    && add_rm_operand(decoder, &modrm, bits, 1));
        }
        case X86_DECODE_FORM_LEA: {
            x86_modrm modrm;

            if (!decode_modrm(decoder, &modrm)) {
                return 0;
            }
            if (modrm.is_register) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            return add_register_operand(
                    decoder,
                    modrm.reg,
                    decoder->operand_bits)
                && add_rm_operand(
                    decoder,
                    &modrm,
                    decoder->operand_bits,
                    0);
        }
        case X86_DECODE_FORM_POP_RM: {
            x86_modrm modrm;

            if (opcode == UINT8_C(0x8f)
                && decoder->position < decoder->code_size
                && (decoder->code[decoder->position] & UINT8_C(0x1f)) >= 8) {
                return decode_xop(decoder);
            }

            bits = decoder->mode == CDISASM_MODE_64
                ? (decoder->operand_override ? 16u : 64u)
                : decoder->operand_bits;
            if (!decode_modrm(decoder, &modrm)) {
                return 0;
            }
            if (modrm.reg3 != 0) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            return add_rm_operand(decoder, &modrm, bits, 1);
        }
        case X86_DECODE_FORM_NOP_XCHG:
            if (decoder->repeat_prefix == 0xf3
                && decoder_has_caps(decoder, X86_CAP_PAUSE)) {
                decoder->name_id = CDISASM_X86_NAME_PAUSE;
                return 1;
            }
            if ((decoder->rex & 1u) != 0) {
                decoder->name_id = CDISASM_X86_NAME_XCHG;
                return add_register_operand(
                        decoder,
                        0,
                        decoder->operand_bits)
                    && add_register_operand(
                        decoder,
                        8,
                        decoder->operand_bits);
            }
            decoder->name_id = CDISASM_X86_NAME_NOP;
            return 1;
        case X86_DECODE_FORM_XCHG_ACCUMULATOR:
            decoder->name_id = descriptor->name_id;
            return add_register_operand(decoder, 0, decoder->operand_bits)
                && add_register_operand(
                    decoder,
                    descriptor->argument
                        + ((decoder->rex & 1u) ? 8u : 0u),
                    decoder->operand_bits);
        case X86_DECODE_FORM_ACCUMULATOR_CONVERT:
            decoder->name_id = decoder->operand_bits == 16
                ? CDISASM_X86_NAME_CBW
                : decoder->operand_bits == 32
                    ? CDISASM_X86_NAME_CWDE
                    : CDISASM_X86_NAME_CDQE;
            return 1;
        case X86_DECODE_FORM_ACCUMULATOR_SIGN_EXTEND:
            decoder->name_id = decoder->operand_bits == 16
                ? CDISASM_X86_NAME_CWD
                : decoder->operand_bits == 32
                    ? CDISASM_X86_NAME_CDQ
                    : CDISASM_X86_NAME_CQO;
            return 1;
        case X86_DECODE_FORM_FAR_CALL:
        case X86_DECODE_FORM_FAR_JUMP:
            if (decoder->mode == CDISASM_MODE_64) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return decoder_fail(
                decoder,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        case X86_DECODE_FORM_FLAGS_STACK:
            bits = decoder->mode == CDISASM_MODE_64
                ? (decoder->operand_override ? 16u : 64u)
                : decoder->operand_bits;
            decoder->name_id = descriptor->argument == 0
                ? (bits == 16
                    ? CDISASM_X86_NAME_PUSHF
                    : bits == 32
                        ? CDISASM_X86_NAME_PUSHFD
                        : CDISASM_X86_NAME_PUSHFQ)
                : (bits == 16
                    ? CDISASM_X86_NAME_POPF
                    : bits == 32
                        ? CDISASM_X86_NAME_POPFD
                        : CDISASM_X86_NAME_POPFQ);
            return 1;
        case X86_DECODE_FORM_MOFFS:
            return decode_moffs(decoder, opcode);
        case X86_DECODE_FORM_STRING:
            return decode_string_instruction(decoder, opcode);
        case X86_DECODE_FORM_TEST_ACCUMULATOR:
            bits = descriptor->argument == 0
                ? decoder->operand_bits
                : descriptor->argument;
            decoder->name_id = descriptor->name_id;
            return add_register_operand(decoder, 0, bits)
                && add_immediate_operand(
                    decoder,
                    bits == 64 ? 32u : bits,
                    bits == 64);
        case X86_DECODE_FORM_MOV_IMMEDIATE_REGISTER:
            return decode_mov_immediate_register(decoder, opcode);
        case X86_DECODE_FORM_GROUP2:
            return decode_group2(decoder, opcode);
        case X86_DECODE_FORM_RETURN_IMMEDIATE:
            decoder->name_id = descriptor->name_id;
            return add_immediate_operand(
                decoder,
                descriptor->argument,
                0);
        case X86_DECODE_FORM_MOV_RM_IMMEDIATE:
            return decode_mov_rm_immediate(decoder, opcode);
        case X86_DECODE_FORM_ENTER:
            return decode_enter(decoder);
        case X86_DECODE_FORM_INT_IMMEDIATE:
            decoder->name_id = descriptor->name_id;
            return add_immediate_operand(
                decoder,
                descriptor->argument,
                0);
        case X86_DECODE_FORM_INTO:
            if (decoder->mode == CDISASM_MODE_64) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            return 1;
        case X86_DECODE_FORM_IRET:
            decoder->name_id = decoder->operand_bits == 16
                ? CDISASM_X86_NAME_IRET
                : decoder->operand_bits == 32
                    ? CDISASM_X86_NAME_IRETD
                    : CDISASM_X86_NAME_IRETQ;
            return 1;
        case X86_DECODE_FORM_ASCII_IMMEDIATE:
            if (decoder->mode == CDISASM_MODE_64) {
                return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            return add_immediate_operand(
                decoder,
                descriptor->argument,
                0);
        case X86_DECODE_FORM_SALC_UDB:
            decoder->name_id = decoder->mode == CDISASM_MODE_64
                ? CDISASM_X86_NAME_UDB
                : CDISASM_X86_NAME_SALC;
            return 1;
        case X86_DECODE_FORM_LOOP:
            decoder->name_id = descriptor->name_id;
            if (descriptor->argument == 3) {
                decoder->name_id = decoder->address_bits == 16
                    ? CDISASM_X86_NAME_JCXZ
                    : decoder->address_bits == 32
                        ? CDISASM_X86_NAME_JECXZ
                        : CDISASM_X86_NAME_JRCXZ;
            }
            return add_relative_operand(decoder, 8);
        case X86_DECODE_FORM_IO_IMMEDIATE:
            return decode_io_immediate(decoder, opcode);
        case X86_DECODE_FORM_CALL_RELATIVE:
            decoder->name_id = descriptor->name_id;
            return add_relative_operand(
                decoder,
                decoder->mode == CDISASM_MODE_64
                    ? 32u
                    : decoder->operand_bits);
        case X86_DECODE_FORM_JUMP_RELATIVE:
            decoder->name_id = descriptor->name_id;
            return add_relative_operand(
                decoder,
                descriptor->argument == 8
                    ? 8u
                    : decoder->mode == CDISASM_MODE_64
                        ? 32u
                        : decoder->operand_bits);
        case X86_DECODE_FORM_IO_DX:
            return decode_io_dx(decoder, opcode);
        case X86_DECODE_FORM_GROUP3:
            return decode_group3(decoder, opcode);
        case X86_DECODE_FORM_GROUP4:
            return decode_group4(decoder);
        case X86_DECODE_FORM_GROUP5:
            return decode_group5(decoder);
        case X86_DECODE_FORM_ESCAPE_0F:
            return decode_two_byte(decoder);
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
}


static int decode_two_byte_binary(
    x86_decoder *decoder,
    cdisasm_x86_name_id name_id,
    unsigned int bits)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = name_id;
    return add_register_operand(decoder, modrm.reg, bits)
        && add_rm_operand(decoder, &modrm, bits, 1);
}

static int decode_undefined_rm(
    x86_decoder *decoder,
    cdisasm_x86_name_id name_id,
    unsigned int bits)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = name_id;
    return add_register_operand(decoder, modrm.reg, bits)
        && add_rm_operand(decoder, &modrm, bits, 1);
}

static int decode_selector_query(
    x86_decoder *decoder,
    cdisasm_x86_name_id name_id)
{
    x86_modrm modrm;
    unsigned int source_bits;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    source_bits = modrm.is_register && decoder->operand_bits != 16 ? 32u : 16u;
    decoder->name_id = name_id;
    return add_register_operand(decoder, modrm.reg, decoder->operand_bits)
        && add_rm_operand(decoder, &modrm, source_bits, 1);
}

static int decode_movx(x86_decoder *decoder, uint8_t opcode)
{
    x86_modrm modrm;
    unsigned int source_bits = (opcode == 0xb6 || opcode == 0xbe) ? 8u : 16u;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = opcode < 0xbe ? CDISASM_X86_NAME_MOVZX : CDISASM_X86_NAME_MOVSX;
    return add_register_operand(decoder, modrm.reg, decoder->operand_bits)
        && add_rm_operand(decoder, &modrm, source_bits, 1);
}

static int decode_double_shift(x86_decoder *decoder, uint8_t opcode)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = opcode == 0xa4 || opcode == 0xa5
        ? CDISASM_X86_NAME_SHLD
        : CDISASM_X86_NAME_SHRD;
    if (!add_rm_operand(decoder, &modrm, decoder->operand_bits, 1)
        || !add_register_operand(decoder, modrm.reg, decoder->operand_bits)) {
        return 0;
    }
    return (opcode & 1u) != 0
        ? add_named_register_operand(
            decoder,
            CDISASM_REG_CL,
            8,
            CDISASM_OPERAND_FLAG_IMPLICIT)
        : add_immediate_operand(decoder, 8, 0);
}

static int decode_bit_register(
    x86_decoder *decoder,
    cdisasm_x86_name_id name_id,
    int lockable)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = name_id;
    if (lockable && !modrm.is_register) {
        decoder->lock_allowed = 1;
    }
    return add_rm_operand(decoder, &modrm, decoder->operand_bits, 1)
        && add_register_operand(decoder, modrm.reg, decoder->operand_bits);
}

static int decode_group8(x86_decoder *decoder)
{
    static const cdisasm_x86_name_id name_ids[4] = {
        CDISASM_X86_NAME_BT, CDISASM_X86_NAME_BTS,
        CDISASM_X86_NAME_BTR, CDISASM_X86_NAME_BTC
    };
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.reg3 < 4) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->name_id = name_ids[modrm.reg3 - 4];
    if (modrm.reg3 != 4 && !modrm.is_register) {
        decoder->lock_allowed = 1;
    }
    return add_rm_operand(decoder, &modrm, decoder->operand_bits, 1)
        && add_immediate_operand(decoder, 8, 0);
}

static int decode_control_debug_move(x86_decoder *decoder, uint8_t opcode)
{
    uint8_t modrm;
    unsigned int special_index;
    unsigned int gpr_index;
    int is_control = opcode == 0x20 || opcode == 0x22;
    unsigned int gpr_bits = decoder->mode == CDISASM_MODE_64 ? 64u : 32u;
    cdisasm_x86_reg_id special_id;

    decoder_require_caps(decoder, X86_CAP_80386);

    /* MOV CR/DR consumes one ModRM byte but architecturally ignores mod. */
    decoder->encoding.modrm_offset = (uint8_t)decoder->position;
    if (!read_u8(decoder, &modrm)) {
        return 0;
    }
    decoder->encoding.modrm = modrm;
    special_index = ((unsigned int)modrm >> 3) & 7u;
    gpr_index = (unsigned int)modrm & 7u;
    if (is_control && (decoder->rex & 4u) != 0) {
        special_index += 8u;
    }
    if ((decoder->rex & 1u) != 0) {
        gpr_index += 8u;
    }

    if (is_control) {
        if (special_index != 0 && special_index != 2 && special_index != 3
            && special_index != 4
            && !(special_index == 8 && decoder->mode == CDISASM_MODE_64)) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else if ((decoder->rex & 4u) != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (is_control && special_index == 4) {
        decoder_require_caps(decoder, X86_CAP_PENTIUM);
    } else if (is_control && special_index == 8) {
        decoder_require_caps(decoder, X86_CAP_AMD64);
    }

    special_id = (cdisasm_x86_reg_id)((is_control
        ? CDISASM_X86_REG_CR0
        : CDISASM_X86_REG_DR0)
        + special_index);
    decoder->name_id = CDISASM_X86_NAME_MOV;
    decoder->groups |= CDISASM_GROUP_PRIVILEGED;

    if (opcode == 0x20 || opcode == 0x21) {
        return add_register_operand(decoder, gpr_index, gpr_bits)
            && add_named_register_operand(
                decoder,
                special_id,
                gpr_bits,
                0);
    }
    return add_named_register_operand(
            decoder,
            special_id,
            gpr_bits,
            0)
        && add_register_operand(decoder, gpr_index, gpr_bits);
}

static int decode_push_pop_fs_gs(x86_decoder *decoder, uint8_t opcode)
{
    decoder->name_id = opcode == 0xa0 || opcode == 0xa8
        ? CDISASM_X86_NAME_PUSH
        : CDISASM_X86_NAME_POP;
    decoder_require_caps(decoder, X86_CAP_80386);
    return add_segment_register_operand(decoder, opcode < 0xa8 ? 4u : 5u);
}

static int decode_waitpkg_register(
    x86_decoder *decoder,
    const x86_modrm *modrm,
    cdisasm_x86_name_id name_id,
    unsigned int bits)
{
#if !USE_EXTRA_OPCODES
    (void)modrm;
    (void)name_id;
    (void)bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder_require_extra(decoder, CDISASM_X86_GROUP_WAITPKG);
    return add_register_operand_access(
        decoder, modrm->rm, bits, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_cache_line_instruction(
    x86_decoder *decoder,
    const x86_modrm *modrm,
    cdisasm_x86_name_id name_id,
    uint64_t capability)
{
    if (modrm->is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)capability;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder_require_caps(decoder, capability);
    if (!add_rm_operand(decoder, modrm, 8u, 1)) {
        return 0;
    }
    decoder->operand[decoder->operand_count - 1].flags |=
        CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
    return set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_non_temporal_simd_store(
    x86_decoder *decoder,
    uint8_t opcode)
{
    x86_modrm modrm;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    uint64_t capability;
    unsigned int memory_bits;
    int mmx_source = 0;

    /* These are the complete legacy 0F 2B and 0F E7 store rows, including
     * their scalar SSE4a and MMX collisions.  REX2.R4 does not extend either
     * XMM or MMX sources; ordinary REX/REX2.R still extends XMM0--XMM15. */
    if (decoder->rex2_present) {
        decoder->modrm_reg_high = 0;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }

    /* Consume the complete address before classifying a reserved selector,
     * so a short SIB/displacement remains TRUNCATED rather than INVALID. */
    if (modrm.is_register || decoder->lock_prefix
        || (decoder->rex2_present && !cpu_has_apx_f(decoder->cpu_id))) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (opcode == UINT8_C(0xe7)) {
        if (decoder->repeat_prefix != 0) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (decoder->operand_override) {
            name_id = CDISASM_X86_NAME_MOVNTDQ;
            form_id = UINT16_C(1691);
            capability = X86_CAP_SSE2;
            memory_bits = 128u;
        } else {
            name_id = CDISASM_X86_NAME_MOVNTQ;
            form_id = UINT16_C(1696);
            capability = X86_CAP_MMX;
            memory_bits = 64u;
            mmx_source = 1;
        }
    } else if (opcode == UINT8_C(0x2b)) {
        if (decoder->repeat_prefix == UINT8_C(0xf3)) {
            name_id = CDISASM_X86_NAME_MOVNTSS;
            form_id = UINT16_C(1698);
            capability = X86_CAP_SSE4A;
            memory_bits = 32u;
        } else if (decoder->repeat_prefix == UINT8_C(0xf2)) {
            name_id = CDISASM_X86_NAME_MOVNTSD;
            form_id = UINT16_C(1697);
            capability = X86_CAP_SSE4A;
            memory_bits = 64u;
        } else if (decoder->operand_override) {
            name_id = CDISASM_X86_NAME_MOVNTPD;
            form_id = UINT16_C(1694);
            capability = X86_CAP_SSE2;
            memory_bits = 128u;
        } else {
            name_id = CDISASM_X86_NAME_MOVNTPS;
            form_id = UINT16_C(1695);
            capability = X86_CAP_SSE;
            memory_bits = 128u;
        }
    } else {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }

    decoder->name_id = name_id;
    decoder->form_id = form_id;
    decoder_require_caps(decoder, capability);
    if (!add_rm_operand(decoder, &modrm, memory_bits, 1)
        || !set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    if (mmx_source) {
        const cdisasm_x86_reg_id source = mmx_id(modrm.reg3);

        if (source == CDISASM_X86_REG_NONE) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        return add_named_register_operand_access(
            decoder, source, 64u, CDISASM_OPERAND_ACCESS_READ);
    }
    return add_named_register_operand_access(
        decoder, xmm_id(modrm.reg), 128u, CDISASM_OPERAND_ACCESS_READ);
}

static int decode_movnti(x86_decoder *decoder)
{
    x86_modrm modrm;
    unsigned int bits;

    /* MOVNTI is the complete NP/OSZ=0 0F C3 memory row.  Decode the full
     * effective address before validating selectors so truncated SIB and
     * displacement inputs retain precedence over prefix errors. */
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register || decoder->lock_prefix
        || decoder->repeat_prefix != 0 || decoder->operand_override) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decoder_has_caps(decoder, X86_CAP_SSE2)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    bits = decoder->mode == CDISASM_MODE_64
            && (decoder->rex & UINT8_C(0x08)) != 0
        ? 64u
        : 32u;
#if !USE_EXTRA_OPCODES
    (void)bits;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_MOVNTI;
    decoder->form_id = bits == 64u ? UINT16_C(1693) : UINT16_C(1692);
    decoder_require_caps(decoder, X86_CAP_SSE2);
    return add_rm_operand(decoder, &modrm, bits, 1)
        && set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_WRITE)
        && add_register_operand_access(
            decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ);
#endif
}

#if USE_EXTRA_OPCODES
static int add_unsized_state_memory_operand(
    x86_decoder *decoder,
    const x86_modrm *modrm,
    cdisasm_operand_access access)
{
    if (!add_rm_operand(decoder, modrm, 8u, 1)) {
        return 0;
    }
    /* FXSAVE areas exceed the ordinary uint8 byte-size range and XSAVE areas
     * are component-dependent.  Preserve that semantic instead of wrapping a
     * concrete size or pretending the access is a scalar memory operand. */
    decoder->operand[decoder->operand_count - 1u].size =
        CDISASM_X86_OPERAND_SIZE_VARIABLE;
    return set_last_operand_access(decoder, access);
}
#endif

static int cpu_has_ptwrite(cdisasm_x86_cpu_id cpu_id)
{
    /* This mirrors the pinned XED chip masks used for public bit 244.  The
     * family ID lies beyond the decoder core's older two-word capability
     * cache, so keep the exact profile check explicit here.  The public
     * PTWRITE group is attached from the successfully decoded name. */
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_ALDER_LAKE:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_CELERON_N4020:
        case CDISASM_CPU_PENTIUM_SILVER_N6000:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_ARROW_LAKE:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        default:
            return 0;
    }
}

static int decode_system_0fae(x86_decoder *decoder)
{
    x86_modrm modrm;
    unsigned int bits;
    uint8_t selector;

    /* F2/F3 refine this row even when a redundant 66 is also present.  With
     * no repeat selector, 66 selects TPAUSE/CLWB-family encodings. */
    selector = decoder->repeat_prefix != 0
        ? decoder->repeat_prefix
        : (decoder->operand_override ? UINT8_C(0x66) : 0);
    if (selector != 0
        && selector != UINT8_C(0xf2)
        && selector != UINT8_C(0xf3)
        && selector != UINT8_C(0x66)) {
        return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->lock_prefix) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (selector == 0) {
        if (modrm.reg3 == 7 && !modrm.is_register) {
            return decode_cache_line_instruction(
                decoder, &modrm, CDISASM_X86_NAME_CLFLUSH,
                X86_CAP_CLFLUSH);
        }
        if (!modrm.is_register
            && (modrm.reg3 == 0 || modrm.reg3 == 1
                || modrm.reg3 == 4 || modrm.reg3 == 5
                || modrm.reg3 == 6)) {
            const int wide = decoder->mode == CDISASM_MODE_64
                && (decoder->rex & UINT8_C(8)) != 0;

            if (decoder->rex2_present) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
#if !USE_EXTRA_OPCODES
            (void)wide;
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
            if (modrm.reg3 <= 1) {
                decoder->name_id = modrm.reg3 == 0
                    ? (wide ? CDISASM_X86_NAME_FXSAVE64
                            : CDISASM_X86_NAME_FXSAVE)
                    : (wide ? CDISASM_X86_NAME_FXRSTOR64
                            : CDISASM_X86_NAME_FXRSTOR);
                decoder_require_caps(decoder, X86_CAP_FXSR);
                return add_unsized_state_memory_operand(
                    decoder, &modrm,
                    modrm.reg3 == 0
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ);
            }
            decoder->name_id = modrm.reg3 == 4
                ? (wide ? CDISASM_X86_NAME_XSAVE64
                        : CDISASM_X86_NAME_XSAVE)
                : modrm.reg3 == 5
                    ? (wide ? CDISASM_X86_NAME_XRSTOR64
                            : CDISASM_X86_NAME_XRSTOR)
                    : (wide ? CDISASM_X86_NAME_XSAVEOPT64
                            : CDISASM_X86_NAME_XSAVEOPT);
            decoder_require_extra(
                decoder,
                modrm.reg3 == 6
                    ? CDISASM_X86_GROUP_XSAVEOPT
                    : CDISASM_X86_GROUP_XSAVE);
            return add_unsized_state_memory_operand(
                decoder, &modrm,
                modrm.reg3 == 5
                    ? CDISASM_OPERAND_ACCESS_READ
                    : CDISASM_OPERAND_ACCESS_READ_WRITE);
#endif
        }
        if (!modrm.is_register
            && (modrm.reg3 == 2 || modrm.reg3 == 3)) {
            decoder_require_caps(decoder, X86_CAP_SSE);
            decoder->name_id = modrm.reg3 == 2
                ? CDISASM_X86_NAME_LDMXCSR
                : CDISASM_X86_NAME_STMXCSR;
            return add_rm_operand(decoder, &modrm, 32u, 1);
        }
        if (modrm.is_register && modrm.reg3 >= 5) {
            decoder->name_id = modrm.reg3 == 5
                ? CDISASM_X86_NAME_LFENCE
                : modrm.reg3 == 6
                    ? CDISASM_X86_NAME_MFENCE
                    : CDISASM_X86_NAME_SFENCE;
            decoder_require_caps(
                decoder,
                modrm.reg3 == 7 ? X86_CAP_SSE : X86_CAP_SSE2);
            return 1;
        }
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (selector == UINT8_C(0xf2)) {
        /* F2 owns exactly /6 with mod=11 (UMWAIT); every other shape in this
         * mandatory-prefix row is reserved. */
        if (modrm.reg3 != 6 || !modrm.is_register) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        return decode_waitpkg_register(
            decoder,
            &modrm,
            CDISASM_X86_NAME_UMWAIT,
            32u);
    }
    if (selector == UINT8_C(0x66)) {
        if (!modrm.is_register) {
            if (modrm.reg3 == 6) {
                return decode_cache_line_instruction(
                    decoder, &modrm, CDISASM_X86_NAME_CLWB,
                    X86_CAP_CLWB);
            }
            if (modrm.reg3 == 7) {
                return decode_cache_line_instruction(
                    decoder, &modrm, CDISASM_X86_NAME_CLFLUSHOPT,
                    X86_CAP_CLFLUSHOPT);
            }
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        if (modrm.reg3 != 6) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        return decode_waitpkg_register(
            decoder,
            &modrm,
            CDISASM_X86_NAME_TPAUSE,
            32u);
    }

    if (modrm.reg3 == 4) {
        /* PTWRITE's F3 is a refining opcode selector.  The OSZ=0 contract
         * rejects 66 even when F3 is the rightmost repeat-class prefix;
         * address-size and segment overrides remain ordinary addressing
         * inputs.  GPRy is dword in every mode unless effective W selects a
         * qword in 64-bit mode.  REX.R/REX2.R/R4 do not extend the /4 opcode
         * field, while B/B4 continue to extend the explicit source. */
        if (decoder->operand_override) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        bits = decoder->mode == CDISASM_MODE_64
                && (decoder->rex & UINT8_C(8)) != 0
            ? 64u
            : 32u;
        if (!cpu_has_ptwrite(decoder->cpu_id)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        (void)bits;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_PTWRITE;
        decoder->form_id = modrm.is_register
            ? UINT16_C(2438) : UINT16_C(2439);
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (modrm.is_register && modrm.reg3 <= 3) {
        static const cdisasm_x86_name_id names[4] = {
            CDISASM_X86_NAME_RDFSBASE, CDISASM_X86_NAME_RDGSBASE,
            CDISASM_X86_NAME_WRFSBASE, CDISASM_X86_NAME_WRGSBASE
        };

        if (decoder->mode != CDISASM_MODE_64 || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        bits = (decoder->rex & UINT8_C(8)) != 0 ? 64u : 32u;
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)bits;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = names[modrm.reg3];
        decoder_require_extra(decoder, CDISASM_X86_GROUP_FSGSBASE);
        return add_register_operand_access(
            decoder, modrm.rm, bits,
            modrm.reg3 <= 1
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ);
#endif
    }
    if (modrm.reg3 == 6 && modrm.is_register) {
        return decode_waitpkg_register(
            decoder,
            &modrm,
            CDISASM_X86_NAME_UMONITOR,
            decoder->address_bits);
    }
    if (modrm.reg3 == 5 && !modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (modrm.reg3 == 7) {
        /* F3 0F AE /7 is reserved for both register and memory forms. */
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!((modrm.reg3 == 5 && modrm.is_register)
          || (modrm.reg3 == 6 && !modrm.is_register))) {
        return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    bits = decoder->mode == CDISASM_MODE_64 && (decoder->rex & 8u) != 0
        ? 64u
        : 32u;

#if !USE_EXTRA_OPCODES
    (void)bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder_require_extra(decoder, CDISASM_X86_GROUP_CET_SS);
    if (modrm.reg3 == 5) {
        decoder->name_id = bits == 64u
            ? CDISASM_X86_NAME_INCSSPQ
            : CDISASM_X86_NAME_INCSSPD;
        decoder_require_caps(
            decoder, bits == 64u ? X86_CAP_AMD64 : X86_CAP_80386);
        return add_register_operand_access(
            decoder, modrm.rm, bits, CDISASM_OPERAND_ACCESS_READ);
    }
    decoder->name_id = CDISASM_X86_NAME_CLRSSBSY;
    decoder->groups |= CDISASM_GROUP_PRIVILEGED;
    return add_rm_operand(decoder, &modrm, 64u, 1)
        && set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ_WRITE);
#endif
}

static int decode_endbr(x86_decoder *decoder)
{
    uint8_t suffix;

    if (decoder->repeat_prefix != UINT8_C(0xf3)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!read_u8(decoder, &suffix)) {
        return 0;
    }
    if (suffix == UINT8_C(0xfa) || suffix == UINT8_C(0xfb)) {
        ++decoder->encoding.opcode_size;
        if (decoder_has_caps(decoder, X86_CAP_CET_IBT)) {
            decoder->name_id = suffix == UINT8_C(0xfa)
                ? CDISASM_X86_NAME_ENDBR64
                : CDISASM_X86_NAME_ENDBR32;
        } else {
            decoder->name_id = CDISASM_X86_NAME_NOP;
            decoder_require_caps(decoder, X86_CAP_P6);
        }
        return 1;
    }
    {
        x86_modrm modrm;

        --decoder->position;
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        /* Intel's BHI/IBHF allocation reuses the CET hint-NOP slot.  The
         * complete byte shape is F3 48 0F 1E F8 (REX.W, /7, rax); classify it
         * before the generic multi-byte-NOP fallback so the generated
         * catalog spelling and zero-operand ABI are preserved. */
        if (decoder->mode == CDISASM_MODE_64
            && decoder->repeat_prefix == UINT8_C(0xf3)
            && (decoder->rex & UINT8_C(8)) != 0
            && modrm.is_register && modrm.reg3 == 7u
            && modrm.rm3 == 0u) {
#if USE_EXTRA_OPCODES
            decoder->name_id = CDISASM_X86_NAME_IBHF;
            decoder_require_extra(decoder, CDISASM_X86_GROUP_IBHF);
            return 1;
#else
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
        if (decoder->lock_prefix) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!modrm.is_register || modrm.reg3 != 1) {
            decoder->name_id = CDISASM_X86_NAME_NOP;
            decoder_require_caps(decoder, X86_CAP_P6);
            return add_rm_operand(
                decoder, &modrm, decoder->operand_bits, 1);
        }
        if (decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        if (!decoder_has_extra(decoder, CDISASM_X86_GROUP_CET_SS)) {
            /* Intel specifies RDSSP as a NOP when CET shadow stacks are not
             * enumerated.  Runtime decode flags remain an independent filter
             * once the selected CPU profile does enumerate CET_SS. */
            decoder->name_id = CDISASM_X86_NAME_NOP;
            decoder_require_caps(decoder, X86_CAP_P6);
            return 1;
        }
        {
            unsigned int bits = decoder->mode == CDISASM_MODE_64
                    && (decoder->rex & 8u) != 0
                ? 64u
                : 32u;

            decoder->name_id = bits == 64u
                ? CDISASM_X86_NAME_RDSSPQ
                : CDISASM_X86_NAME_RDSSPD;
            decoder_require_caps(
                decoder, bits == 64u ? X86_CAP_AMD64 : X86_CAP_80386);
            decoder_require_extra(decoder, CDISASM_X86_GROUP_CET_SS);
            return add_register_operand_access(
                decoder, modrm.rm, bits, CDISASM_OPERAND_ACCESS_WRITE);
        }
#endif
    }
}

static int decode_svm_system(x86_decoder *decoder, uint8_t selector)
{
    static const cdisasm_x86_name_id names[8] = {
        CDISASM_X86_NAME_VMRUN, CDISASM_X86_NAME_VMMCALL,
        CDISASM_X86_NAME_VMLOAD, CDISASM_X86_NAME_VMSAVE,
        CDISASM_X86_NAME_STGI, CDISASM_X86_NAME_CLGI,
        CDISASM_X86_NAME_SKINIT, CDISASM_X86_NAME_INVLPGA
    };
    const uint8_t implicit = CDISASM_OPERAND_FLAG_IMPLICIT;

    if (selector >= 8) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
    if (decoder->repeat_prefix != 0 && selector == 1) {
        if (decoder->operand_override) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = decoder_has_caps(decoder, X86_CAP_SEV_ES)
            ? CDISASM_X86_NAME_VMGEXIT
            : CDISASM_X86_NAME_VMMCALL;
        return 1;
    }
    if (decoder->repeat_prefix != 0
        && selector != 0 && selector != 3) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder->name_id = names[selector];
    if (selector == 0) {
        decoder->form_id = UINT16_C(6004);
    } else if (selector == 3) {
        decoder->form_id = UINT16_C(6005);
    }
    if (selector != 1) {
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
    }
    switch (selector) {
        case 0:
        case 2:
            return add_register_operand_flags(
                decoder,
                0,
                decoder->address_bits,
                implicit);
        case 6:
            return add_named_register_operand(
                decoder,
                CDISASM_X86_REG_EAX,
                32,
                implicit);
        case 7:
            return add_register_operand_flags(
                       decoder,
                       0,
                       decoder->address_bits,
                       implicit)
                && add_named_register_operand(
                       decoder,
                       CDISASM_X86_REG_ECX,
                       32,
                       implicit);
        default:
            return 1;
    }
}

static int cpu_has_pconfig(cdisasm_x86_cpu_id cpu_id)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_TIGER_LAKE:
        case CDISASM_CPU_ALDER_LAKE:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_ARROW_LAKE:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        default:
            return 0;
    }
}

static int cpu_has_pbndkb(cdisasm_x86_cpu_id cpu_id)
{
    /* Pinned XED exposes PBNDKB first on Panther Lake.  cdisasm does not
     * currently publish that profile, so do not infer support from adjacent
     * Intel generations; the unrestricted compatibility CPU remains usable. */
    return cpu_id == CDISASM_CPU_X86;
}

static int cpu_has_clzero(cdisasm_x86_cpu_id cpu_id)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_AMD_ZEN:
        case CDISASM_CPU_AMD_ZEN_4:
            return 1;
        default:
            return 0;
    }
}

static int cpu_has_msrlist(cdisasm_x86_cpu_id cpu_id)
{
    /* The checked-in profile snapshot exposes MSRLIST first on DMR. */
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}

static int cpu_has_wrmsrns(cdisasm_x86_cpu_id cpu_id)
{
    /* WRMSRNS shares the same first named profile in the pinned snapshot. */
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}

static int cpu_has_mcommit(cdisasm_x86_cpu_id cpu_id)
{
    /* None of the current named profiles maps to XED's AMD_ZEN2 chip. */
    return cpu_id == CDISASM_CPU_X86;
}

static int cpu_has_monitorx(cdisasm_x86_cpu_id cpu_id)
{
    /* MONITORX/MWAITX share one CPUID/ISA_SET gate in pinned XED. */
    return cpu_id == CDISASM_CPU_X86;
}

static int cpu_has_amd_invlpgb(cdisasm_x86_cpu_id cpu_id)
{
    /* Pinned XED assigns this family only to AMD_FUTURE.  There is no
     * equivalent named cdisasm profile yet, so expose it solely through the
     * unrestricted compatibility profile instead of guessing a generation. */
    return cpu_id == CDISASM_CPU_X86;
}

static int cpu_has_snp(cdisasm_x86_cpu_id cpu_id)
{
    /* SNP has the same AMD_FUTURE-only profile boundary in pinned XED. */
    return cpu_id == CDISASM_CPU_X86;
}

static int cpu_has_rdpru(cdisasm_x86_cpu_id cpu_id)
{
    /* Pinned XED first exposes RDPRU on its AMD_ZEN2 profile.  cdisasm has
     * no named Zen 2 profile, and its existing Zen/Zen 4 profiles are
     * conservative snapshots, so retain only the unrestricted route. */
    return cpu_id == CDISASM_CPU_X86;
}

static int cpu_has_smap(cdisasm_x86_cpu_id cpu_id)
{
    /* This is the exact pinned-XED profile set behind public ISA bit 253.
     * In particular, Haswell and its G1840 derivative precede SMAP in this
     * snapshot, while Broadwell and the listed low-power derivatives have
     * it.  Keep the unrestricted compatibility profile available. */
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_BROADWELL:
        case CDISASM_CPU_SKYLAKE:
        case CDISASM_CPU_GOLDMONT:
        case CDISASM_CPU_AMD_ZEN:
        case CDISASM_CPU_SKYLAKE_SP:
        case CDISASM_CPU_ICE_LAKE:
        case CDISASM_CPU_TIGER_LAKE:
        case CDISASM_CPU_ALDER_LAKE:
        case CDISASM_CPU_AMD_ZEN_4:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_CELERON_G3900:
        case CDISASM_CPU_CELERON_N3350:
        case CDISASM_CPU_CELERON_N4020:
        case CDISASM_CPU_CELERON_G5900:
        case CDISASM_CPU_PENTIUM_SILVER_N6000:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_ARROW_LAKE:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        default:
            return 0;
    }
}

static int cpu_has_fred(cdisasm_x86_cpu_id cpu_id)
{
    /* F2/F3 0F 01 CA belongs to FRED, whose suppressed architectural state
     * is not exactly representable by the fixed public operand ABI.  Still
     * own the allocation on profiles that publish it so it cannot fall back
     * to the no-prefix SMAP spelling. */
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}

static int cpu_has_apx_f(cdisasm_x86_cpu_id cpu_id)
{
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_APX
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}

static int decode_fixed_virtualization_system(
    x86_decoder *decoder,
    const x86_modrm *modrm)
{
    const uint8_t fixed = decoder->encoding.modrm;

    /* CLAC/STAC are the fixed NP 0F 01 CA/CB SMAP allocations.  They write
     * the architectural AC status flag, have no explicit operands, and are
     * CPL0 in every mode.  REX and APX REX2-map-1 payload bits are ignored.
     * Mandatory F2/F3 on CA instead select FRED ERETS/ERETU in 64-bit mode;
     * return that row to the generated catalog fallback because its
     * suppressed stack/control-state contract is not part of this exact
     * SMAP implementation.  It must never alias the no-prefix SMAP forms. */
    if (fixed == UINT8_C(0xca) || fixed == UINT8_C(0xcb)) {
        if (decoder->lock_prefix) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (decoder->repeat_prefix != 0) {
            if (fixed != UINT8_C(0xca)
                || decoder->mode != CDISASM_MODE_64
                || !cpu_has_fred(decoder->cpu_id)) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        if (decoder->operand_override
            || !cpu_has_smap(decoder->cpu_id)
            || (decoder->rex2_present
                && !cpu_has_apx_f(decoder->cpu_id))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = fixed == UINT8_C(0xca)
            ? CDISASM_X86_NAME_CLAC : CDISASM_X86_NAME_STAC;
        decoder->form_id = fixed == UINT8_C(0xca)
            ? UINT16_C(707) : UINT16_C(3158);
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        decoder->prefix_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        return 1;
#endif
    }

    /* PBNDKB is the fixed NP 0F 01 C7 allocation.  It is 64-bit and CPL0
     * only.  RBX/RCX supply pointers and EAX receives status, but all three
     * registers are suppressed architectural state in XED and therefore do
     * not appear as public syntax operands.  Address-size, segment, REX and
     * REX2 prefixes are accepted; LOCK, F2/F3 and 66 are reserved. */
    if (fixed == UINT8_C(0xc7)) {
        if (decoder->mode != CDISASM_MODE_64 || decoder->lock_prefix
            || decoder->repeat_prefix != 0 || decoder->operand_override) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!cpu_has_pbndkb(decoder->cpu_id)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_PBNDKB;
        decoder->form_id = UINT16_C(2039);
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        decoder->prefix_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        return 1;
#endif
    }

    /* 0F 01 C6 is a three-way mandatory-prefix allocation.  F2/F3 select
     * the 64-bit-only MSRLIST operations and accept a redundant 66; NP is
     * WRMSRNS in all architectural modes and reserves 66.  XED classifies
     * all architectural register state as suppressed, so these public forms
     * deliberately have no syntax operands. */
    if (fixed == UINT8_C(0xc6)) {
        const int is_list = decoder->repeat_prefix != 0;

        if (decoder->lock_prefix
            || (is_list && decoder->mode != CDISASM_MODE_64)
            || (!is_list && decoder->operand_override)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (is_list) {
            if (!cpu_has_msrlist(decoder->cpu_id)) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        } else if (!cpu_has_wrmsrns(decoder->cpu_id)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        if (decoder->repeat_prefix == UINT8_C(0xf2)) {
            decoder->name_id = CDISASM_X86_NAME_RDMSRLIST;
            decoder->form_id = UINT16_C(2571);
            decoder->used_msrlist = 1;
            decoder_require_caps(decoder, X86_CAP_AMD64);
        } else if (decoder->repeat_prefix == UINT8_C(0xf3)) {
            decoder->name_id = CDISASM_X86_NAME_WRMSRLIST;
            decoder->form_id = UINT16_C(8892);
            decoder->used_msrlist = 1;
            decoder_require_caps(decoder, X86_CAP_AMD64);
        } else {
            decoder->name_id = CDISASM_X86_NAME_WRMSRNS;
            decoder->form_id = UINT16_C(8893);
            decoder->used_wrmsrns = 1;
        }
        return 1;
#endif
    }

    /* AMD's fixed Group-7 FA/FB row has three disjoint allocations.  NP FA
     * selects MONITORX, NP FB selects MWAITX, and mandatory-F3 FA selects
     * MCOMMIT.  MONITORX/MWAITX require OSZ=0, while MCOMMIT deliberately
     * accepts a redundant 66.  Their accumulator/control registers are XED
     * SUPP state and therefore remain absent from the public operand list. */
    if (fixed == UINT8_C(0xfa) || fixed == UINT8_C(0xfb)) {
        const int is_mcommit = fixed == UINT8_C(0xfa)
            && decoder->repeat_prefix == UINT8_C(0xf3);

        if (decoder->lock_prefix
            || (!is_mcommit && (decoder->repeat_prefix != 0
                || decoder->operand_override))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (is_mcommit) {
            if (!cpu_has_mcommit(decoder->cpu_id)) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
#if !USE_EXTRA_OPCODES
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
            decoder->name_id = CDISASM_X86_NAME_MCOMMIT;
            decoder->form_id = UINT16_C(1629);
            decoder->prefix_flags
                |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
            return 1;
#endif
        }
        if (!cpu_has_monitorx(decoder->cpu_id)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = fixed == UINT8_C(0xfa)
            ? CDISASM_X86_NAME_MONITORX
            : CDISASM_X86_NAME_MWAITX;
        decoder->form_id = fixed == UINT8_C(0xfa)
            ? UINT16_C(1640) : UINT16_C(1822);
        return 1;
#endif
    }

    /* AMD INVLPGB/TLBSYNC and Secure Nested Paging share the fixed FE/FF
     * Group-7 row.  NP selects the AMD_INVLPGB family; F2/F3 select SNP.
     * INVLPGB has an effective-address-size constraint even though its
     * architectural register inputs are suppressed, while TLBSYNC and the
     * SNP forms ignore address size.  A redundant 66 is accepted only when
     * F2/F3 supplies the mandatory-prefix selector. */
    if (fixed == UINT8_C(0xfe) || fixed == UINT8_C(0xff)) {
        const uint8_t repeat = decoder->repeat_prefix;

        if (decoder->lock_prefix
            || (repeat != 0 && repeat != UINT8_C(0xf2)
                && repeat != UINT8_C(0xf3))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (repeat == 0) {
            if (decoder->operand_override
                || (fixed == UINT8_C(0xfe)
                    && decoder->address_bits == 16u)) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            if (!cpu_has_amd_invlpgb(decoder->cpu_id)) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
#if !USE_EXTRA_OPCODES
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
            decoder->name_id = fixed == UINT8_C(0xfe)
                ? CDISASM_X86_NAME_INVLPGB
                : CDISASM_X86_NAME_TLBSYNC;
            decoder->form_id = fixed == UINT8_C(0xfe)
                ? UINT16_C(1410) : UINT16_C(3309);
            decoder->groups |= CDISASM_GROUP_PRIVILEGED;
            return 1;
#endif
        }

        if ((repeat == UINT8_C(0xf3)
                || (repeat == UINT8_C(0xf2)
                    && fixed == UINT8_C(0xfe)))
            && decoder->mode != CDISASM_MODE_64) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!cpu_has_snp(decoder->cpu_id)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        decoder->prefix_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        if (repeat == UINT8_C(0xf2) && fixed == UINT8_C(0xfe)) {
            decoder->name_id = CDISASM_X86_NAME_RMPUPDATE;
            decoder->form_id = UINT16_C(2633);
            return add_named_register_operand(
                       decoder, CDISASM_X86_REG_RAX, 64u,
                       CDISASM_OPERAND_FLAG_IMPLICIT)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_named_register_operand(
                       decoder, CDISASM_X86_REG_RCX, 64u,
                       CDISASM_OPERAND_FLAG_IMPLICIT)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        if (repeat == UINT8_C(0xf2)) {
            decoder->name_id = CDISASM_X86_NAME_PVALIDATE;
            decoder->form_id = UINT16_C(2487);
            return add_named_register_operand(
                       decoder, CDISASM_X86_REG_RAX, 64u,
                       CDISASM_OPERAND_FLAG_IMPLICIT)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_named_register_operand(
                       decoder, CDISASM_X86_REG_ECX, 32u,
                       CDISASM_OPERAND_FLAG_IMPLICIT)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ)
                && add_named_register_operand(
                       decoder, CDISASM_X86_REG_EDX, 32u,
                       CDISASM_OPERAND_FLAG_IMPLICIT)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        if (fixed == UINT8_C(0xfe)) {
            decoder->name_id = CDISASM_X86_NAME_RMPADJUST;
            decoder->form_id = UINT16_C(2632);
            return add_named_register_operand(
                       decoder, CDISASM_X86_REG_RAX, 64u,
                       CDISASM_OPERAND_FLAG_IMPLICIT)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ_WRITE)
                && add_named_register_operand(
                       decoder, CDISASM_X86_REG_RCX, 64u,
                       CDISASM_OPERAND_FLAG_IMPLICIT)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ)
                && add_named_register_operand(
                       decoder, CDISASM_X86_REG_RDX, 64u,
                       CDISASM_OPERAND_FLAG_IMPLICIT)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        decoder->name_id = CDISASM_X86_NAME_PSMASH;
        decoder->form_id = UINT16_C(2370);
        return add_named_register_operand(
                   decoder, CDISASM_X86_REG_RAX, 64u,
                   CDISASM_OPERAND_FLAG_IMPLICIT)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_READ_WRITE);
#endif
    }

    /* PCONFIG is the fixed NP/OSZ=0 0F 01 C5 allocation.  Address-size,
     * segment, and ordinary REX prefixes are ignored, while LOCK, F2/F3, and
     * 66 are illegal.  REX2 reaches this branch only through the explicit
     * map-1 whitelist and gains its independent APX-F requirement there. */
    if (fixed == UINT8_C(0xc5)) {
        if (decoder->lock_prefix || decoder->repeat_prefix != 0
            || decoder->operand_override) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!cpu_has_pconfig(decoder->cpu_id)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_PCONFIG;
        decoder->form_id = (decoder->rex & 8u) != 0
            ? UINT16_C(2085) : UINT16_C(2084);
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        decoder->prefix_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        return 1;
#endif
    }

    /* AMD CLZERO is the single fixed 0F 01 FC allocation.  Its address input
     * is architecturally implicit in the accumulator and is intentionally
     * omitted from the public operand list.  XED accepts redundant legacy,
     * operand/address-size, segment, REX, and REX2 prefixes; only LOCK is
     * illegal.  Keep the profile boundary structural so it survives an
     * extras-OFF build, and do not consume the neighboring INVLPG memory row. */
    if (fixed == UINT8_C(0xfc)) {
        if (decoder->lock_prefix) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!cpu_has_clzero(decoder->cpu_id)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_CLZERO;
        decoder->form_id = UINT16_C(719);
        return 1;
#endif
    }

    /* RDPRU is the single CPL3 AMD allocation at 0F 01 FD.  EDX:EAX receives
     * the selected processor register and ECX supplies its selector, but XED
     * marks all three registers suppressed, leaving no public syntax
     * operands.  Operand/address-size, segment, F2/F3, REX, and REX2 prefixes
     * are accepted as redundant; only LOCK is illegal. */
    if (fixed == UINT8_C(0xfd)) {
        if (decoder->lock_prefix) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!cpu_has_rdpru(decoder->cpu_id)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_RDPRU;
        decoder->form_id = UINT16_C(2578);
        return 1;
#endif
    }

    if (decoder->repeat_prefix == UINT8_C(0xf2)
        && (fixed == UINT8_C(0xe8) || fixed == UINT8_C(0xe9))) {
        if (decoder->lock_prefix || decoder->operand_override
            || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = fixed == UINT8_C(0xe8)
            ? CDISASM_X86_NAME_XSUSLDTRK
            : CDISASM_X86_NAME_XRESLDTRK;
        decoder_require_extra(decoder, CDISASM_X86_GROUP_TSX_LDTRK);
        return 1;
#endif
    }
    if (decoder->repeat_prefix == UINT8_C(0xf3)
        && fixed >= UINT8_C(0xec) && fixed <= UINT8_C(0xef)) {
        static const cdisasm_x86_name_id uintr_names[4] = {
            CDISASM_X86_NAME_UIRET,
            CDISASM_X86_NAME_TESTUI,
            CDISASM_X86_NAME_CLUI,
            CDISASM_X86_NAME_STUI
        };

        if (decoder->mode != CDISASM_MODE_64 || decoder->lock_prefix
            || decoder->operand_override || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        (void)uintr_names;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = uintr_names[fixed - UINT8_C(0xec)];
        decoder_require_extra(decoder, CDISASM_X86_GROUP_UINTR);
        if (decoder->name_id == CDISASM_X86_NAME_UIRET) {
            decoder->groups |= CDISASM_GROUP_INTERRUPT_RETURN;
        }
        return 1;
#endif
    }

    /* Architectural fixed ModRM opcodes sharing the 0F 01 system row. */
    if (decoder->encoding.modrm == UINT8_C(0xd0)
        || decoder->encoding.modrm == UINT8_C(0xd1)
        || decoder->encoding.modrm == UINT8_C(0xc8)
        || decoder->encoding.modrm == UINT8_C(0xc9)
        || decoder->encoding.modrm == UINT8_C(0xf9)
        || decoder->encoding.modrm == UINT8_C(0xee)
        || decoder->encoding.modrm == UINT8_C(0xef)) {
        if (decoder->lock_prefix || decoder->repeat_prefix
            || decoder->operand_override
            || (decoder->rex2_present
                && fixed != UINT8_C(0xc8)
                && fixed != UINT8_C(0xc9))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        (void)fixed;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        if (fixed == UINT8_C(0xd0) || fixed == UINT8_C(0xd1)) {
            decoder->name_id = fixed == UINT8_C(0xd0)
                ? CDISASM_X86_NAME_XGETBV
                : CDISASM_X86_NAME_XSETBV;
            decoder_require_extra(decoder, CDISASM_X86_GROUP_XSAVE);
            if (fixed == UINT8_C(0xd1)) {
                decoder->groups |= CDISASM_GROUP_PRIVILEGED;
            }
            return 1;
        }
        if (fixed == UINT8_C(0xc8) || fixed == UINT8_C(0xc9)) {
            decoder->name_id = fixed == UINT8_C(0xc8)
                ? CDISASM_X86_NAME_MONITOR
                : CDISASM_X86_NAME_MWAIT;
            decoder->groups |= CDISASM_GROUP_PRIVILEGED;
            return 1;
        }
        if (fixed == UINT8_C(0xf9)) {
            decoder->name_id = CDISASM_X86_NAME_RDTSCP;
            return 1;
        }

        decoder->name_id = fixed == UINT8_C(0xee)
            ? CDISASM_X86_NAME_RDPKRU
            : CDISASM_X86_NAME_WRPKRU;
        decoder_require_extra(decoder, CDISASM_X86_GROUP_PKU);
        return 1;
#endif
    }
    if ((fixed == UINT8_C(0xc0) || fixed == UINT8_C(0xcf)
            || fixed == UINT8_C(0xd7))
        && decoder->repeat_prefix == 0 && !decoder->operand_override) {
        if (decoder->lock_prefix || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = fixed == UINT8_C(0xc0)
            ? CDISASM_X86_NAME_ENCLV
            : fixed == UINT8_C(0xcf)
                ? CDISASM_X86_NAME_ENCLS
                : CDISASM_X86_NAME_ENCLU;
        decoder_require_extra(decoder, CDISASM_X86_GROUP_SGX);
        if (decoder->name_id == CDISASM_X86_NAME_ENCLS) {
            decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        }
        return 1;
#endif
    }
    if (!modrm->is_register) {
        return 0;
    }
    if (decoder->encoding.modrm == UINT8_C(0xe8)) {
        if (decoder->lock_prefix || decoder->operand_override
            || (decoder->repeat_prefix != 0
                && decoder->repeat_prefix != UINT8_C(0xf2))) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        /* F2 0F 01 E8 is XSUSLDTRK, not a prefixed SERIALIZE spelling. */
        if (decoder->repeat_prefix == UINT8_C(0xf2)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_SERIALIZE;
        decoder_require_caps(decoder, X86_CAP_SERIALIZE);
        return 1;
#endif
    }
    if (modrm->reg3 == 2
        && (modrm->rm3 == 5 || modrm->rm3 == 6)) {
        if (decoder->lock_prefix || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = modrm->rm3 == 5
            ? CDISASM_X86_NAME_XEND
            : CDISASM_X86_NAME_XTEST;
        if (modrm->rm3 == 5) {
            decoder_require_extra(decoder, CDISASM_X86_GROUP_RTM);
        } else {
            decoder_require_hle_or_rtm(decoder);
        }
        return 1;
#endif
    }
    if (modrm->reg3 == 3) {
        return decode_svm_system(decoder, modrm->rm3);
    }
    if (modrm->reg3 == 0 && modrm->rm3 >= 1 && modrm->rm3 <= 4) {
        static const cdisasm_x86_name_id names[4] = {
            CDISASM_X86_NAME_VMCALL,
            CDISASM_X86_NAME_VMLAUNCH,
            CDISASM_X86_NAME_VMRESUME,
            CDISASM_X86_NAME_VMXOFF
        };

        if (decoder->repeat_prefix != 0 || decoder->operand_override) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = names[modrm->rm3 - 1u];
        if (decoder->name_id == CDISASM_X86_NAME_VMRESUME
            || decoder->name_id == CDISASM_X86_NAME_VMXOFF) {
            decoder->form_id = decoder->name_id
                    == CDISASM_X86_NAME_VMRESUME
                ? UINT16_C(6003) : UINT16_C(6052);
            decoder->prefix_flags
                |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        }
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        return 1;
    }
    if (modrm->reg3 == 2 && modrm->rm3 == 4) {
        if (decoder->repeat_prefix != 0 || decoder->operand_override) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = CDISASM_X86_NAME_VMFUNC;
        return 1;
    }
    return 0;
}

/* Return -1 when Group 7 does not select a CET shadow-stack instruction. */
static int decode_cet_group7(
    x86_decoder *decoder,
    const x86_modrm *modrm)
{
    if (decoder->repeat_prefix != UINT8_C(0xf3) || modrm->reg3 != 5) {
        return -1;
    }
    /* F3 0F 01 EC..EF is the disjoint 64-bit UINTR fixed-opcode row. */
    if (decoder->mode == CDISASM_MODE_64 && modrm->is_register
        && decoder->encoding.modrm >= UINT8_C(0xec)
        && decoder->encoding.modrm <= UINT8_C(0xef)) {
        return -1;
    }
    if (decoder->lock_prefix) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (modrm->is_register
        && decoder->encoding.modrm != UINT8_C(0xe8)
        && decoder->encoding.modrm != UINT8_C(0xea)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder_require_extra(decoder, CDISASM_X86_GROUP_CET_SS);
    if (modrm->is_register) {
        decoder->name_id = decoder->encoding.modrm == UINT8_C(0xe8)
            ? CDISASM_X86_NAME_SETSSBSY
            : CDISASM_X86_NAME_SAVEPREVSSP;
        if (decoder->name_id == CDISASM_X86_NAME_SETSSBSY) {
            decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        }
        return 1;
    }
    decoder->name_id = CDISASM_X86_NAME_RSTORSSP;
    return add_rm_operand(decoder, modrm, 64u, 1)
        && set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ_WRITE);
#endif
}

static int decode_vmx_read_write(x86_decoder *decoder, uint8_t opcode)
{
    x86_modrm modrm;
    unsigned int bits = decoder->mode == CDISASM_MODE_64 ? 64u : 32u;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->repeat_prefix != 0 || decoder->operand_override) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->name_id = opcode == 0x78
        ? CDISASM_X86_NAME_VMREAD
        : CDISASM_X86_NAME_VMWRITE;
    decoder->groups |= CDISASM_GROUP_PRIVILEGED;
    if (opcode == 0x78) {
        decoder->form_id = modrm.is_register
            ? (bits == 64u ? UINT16_C(6000) : UINT16_C(5999))
            : (bits == 64u ? UINT16_C(6002) : UINT16_C(6001));
        decoder->prefix_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                   decoder, modrm.reg, bits,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    decoder->form_id = modrm.is_register
        ? (bits == 64u ? UINT16_C(6050) : UINT16_C(6048))
        : (bits == 64u ? UINT16_C(6051) : UINT16_C(6049));
    decoder->prefix_flags
        |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    return add_register_operand_access(
            decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ)
        && add_rm_operand(decoder, &modrm, bits, 1)
        && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
}

static int decode_vmx_pointer(x86_decoder *decoder)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!modrm.is_register && modrm.reg3 == 1) {
        const unsigned int bits = decoder->mode == CDISASM_MODE_64
                && (decoder->rex & UINT8_C(8)) != 0
            ? 128u
            : 64u;

        if (decoder->repeat_prefix != 0 || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = bits == 128u
            ? CDISASM_X86_NAME_CMPXCHG16B
            : CDISASM_X86_NAME_CMPXCHG8B;
        decoder->lock_allowed = 1;
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    if (!modrm.is_register
        && (modrm.reg3 == 3 || modrm.reg3 == 4 || modrm.reg3 == 5)) {
        const int wide = decoder->mode == CDISASM_MODE_64
            && (decoder->rex & UINT8_C(8)) != 0;

        if (decoder->lock_prefix || decoder->repeat_prefix
            || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        (void)wide;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        if (modrm.reg3 == 3) {
            decoder->name_id = wide
                ? CDISASM_X86_NAME_XRSTORS64
                : CDISASM_X86_NAME_XRSTORS;
            decoder_require_extra(decoder, CDISASM_X86_GROUP_XSAVES);
            decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        } else if (modrm.reg3 == 4) {
            decoder->name_id = wide
                ? CDISASM_X86_NAME_XSAVEC64
                : CDISASM_X86_NAME_XSAVEC;
            decoder_require_extra(decoder, CDISASM_X86_GROUP_XSAVEC);
        } else {
            decoder->name_id = wide
                ? CDISASM_X86_NAME_XSAVES64
                : CDISASM_X86_NAME_XSAVES;
            decoder_require_extra(decoder, CDISASM_X86_GROUP_XSAVES);
            decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        }
        return add_unsized_state_memory_operand(
            decoder, &modrm,
            modrm.reg3 == 3
                ? CDISASM_OPERAND_ACCESS_READ
                : CDISASM_OPERAND_ACCESS_WRITE);
#endif
    }
    if (modrm.is_register) {
        unsigned int bits = decoder->operand_bits;

        if (decoder->lock_prefix) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (modrm.reg3 != 6 && modrm.reg3 != 7) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (decoder->repeat_prefix != 0) {
            if (decoder->repeat_prefix == UINT8_C(0xf3)
                && modrm.reg3 == 7) {
                const unsigned int rdpid_bits =
                    decoder->mode == CDISASM_MODE_64 ? 64u : 32u;

#if !USE_EXTRA_OPCODES
                (void)rdpid_bits;
                return decoder_fail(
                    decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
                decoder->name_id = CDISASM_X86_NAME_RDPID;
                decoder_require_caps(decoder, X86_CAP_RDPID);
                return add_register_operand_access(
                    decoder, modrm.rm, rdpid_bits,
                    CDISASM_OPERAND_ACCESS_WRITE);
#endif
            }
            /* F3 0F C7 /6 is SENDUIPI in 64-bit mode. */
            if (decoder->repeat_prefix == UINT8_C(0xf3)
                && modrm.reg3 == 6) {
                if (decoder->mode != CDISASM_MODE_64
                    || decoder->operand_override || decoder->rex2_present) {
                    return decoder_fail(
                        decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
                }
#if !USE_EXTRA_OPCODES
                return decoder_fail(
                    decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
                decoder->name_id = CDISASM_X86_NAME_SENDUIPI;
                decoder_require_extra(decoder, CDISASM_X86_GROUP_UINTR);
                return add_register_operand_access(
                    decoder, modrm.rm, 64u,
                    CDISASM_OPERAND_ACCESS_READ);
#endif
            }
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (bits == 64u && decoder->mode != CDISASM_MODE_64) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = modrm.reg3 == 6
            ? CDISASM_X86_NAME_RDRAND
            : CDISASM_X86_NAME_RDSEED;
        decoder_require_extra(
            decoder,
            modrm.reg3 == 6
                ? CDISASM_X86_GROUP_RDRAND
                : CDISASM_X86_GROUP_RDSEED);
        return add_register_operand_access(
            decoder,
            modrm.rm,
            bits,
            CDISASM_OPERAND_ACCESS_WRITE);
#endif
    }
    if (modrm.reg3 == 6) {
        if (decoder->repeat_prefix == 0xf2) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (decoder->repeat_prefix == 0xf3) {
            decoder->name_id = CDISASM_X86_NAME_VMXON;
            decoder->form_id = UINT16_C(6053);
        } else if (decoder->operand_override) {
            decoder->name_id = CDISASM_X86_NAME_VMCLEAR;
        } else {
            decoder->name_id = CDISASM_X86_NAME_VMPTRLD;
        }
    } else if (modrm.reg3 == 7) {
        if (decoder->repeat_prefix != 0 || decoder->operand_override) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = CDISASM_X86_NAME_VMPTRST;
    } else {
        return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    if (decoder->name_id == CDISASM_X86_NAME_VMPTRLD) {
        decoder->form_id = UINT16_C(5997);
    } else if (decoder->name_id == CDISASM_X86_NAME_VMPTRST) {
        decoder->form_id = UINT16_C(5998);
    }
    decoder->groups |= CDISASM_GROUP_PRIVILEGED;
    decoder->prefix_flags
        |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    return add_rm_operand(decoder, &modrm, 64, 1)
        && set_last_operand_access(
               decoder,
               decoder->name_id == CDISASM_X86_NAME_VMPTRST
                   ? CDISASM_OPERAND_ACCESS_WRITE
                   : CDISASM_OPERAND_ACCESS_READ);
}

static int decode_legacy_simd_map(
    x86_decoder *decoder,
    const x86_simd_descriptor *map,
    size_t count,
    uint8_t opcode);
static uint8_t legacy_simd_prefix(const x86_decoder *decoder);

static int cpu_has_keylocker(cdisasm_x86_cpu_id cpu_id)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_TIGER_LAKE:
        case CDISASM_CPU_ALDER_LAKE:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_ARROW_LAKE:
            return 1;
        default:
            return 0;
    }
}

static int cpu_has_hreset(cdisasm_x86_cpu_id cpu_id)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_ALDER_LAKE:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_ARROW_LAKE:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        default:
            return 0;
    }
}

#if USE_EXTRA_OPCODES
static int cpu_has_cldemote(cdisasm_x86_cpu_id cpu_id)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_PENTIUM_SILVER_N6000:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        default:
            return 0;
    }
}
#endif

static int cpu_has_icache_prefetch(cdisasm_x86_cpu_id cpu_id)
{
    /* The pinned XED chip profile has ICACHE_PREFETCH on Granite Rapids,
     * Clearwater Forest and Diamond Rapids.  The latter two named cdisasm
     * profiles are represented; Clearwater Forest is not. */
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_GRANITE_RAPIDS
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}

static int cpu_has_prefetchrst2(cdisasm_x86_cpu_id cpu_id)
{
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}

static int cpu_has_prefetchwt1(cdisasm_x86_cpu_id cpu_id)
{
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_KNIGHTS_MILL;
}

/* 0F 18 is a collision row rather than a uniformly SSE-prefetch row.
 * Memory /0-/3 retain PREFETCHNTA/T0/T1/T2.  Memory /4 promotes from its P6
 * fat-NOP meaning to PREFETCHRST2 on CPUs that enumerate MOVRS.  Memory /6-/7
 * similarly promotes to PREFETCHIT1/0 only in 64-bit mode with an actual
 * 64-bit RIP-relative address on a supporting CPU.  Every register tuple and
 * all unpromoted /4-/7 tuples retain their architectural NOP meaning. */
static int decode_prefetch_row(x86_decoder *decoder)
{
    static const cdisasm_x86_name_id data_prefetch_names[4] = {
        CDISASM_X86_NAME_PREFETCHNTA,
        CDISASM_X86_NAME_PREFETCHT0,
        CDISASM_X86_NAME_PREFETCHT1,
        CDISASM_X86_NAME_PREFETCHT2
    };
    x86_modrm modrm;
    int is_icache_prefetch;
    int is_prefetchrst2;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->lock_prefix) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    is_icache_prefetch = !modrm.is_register && modrm.reg3 >= 6u
        && decoder->mode == CDISASM_MODE_64
        && decoder->address_bits == 64u && modrm.rip_relative
        && cpu_has_icache_prefetch(decoder->cpu_id);
    is_prefetchrst2 = !modrm.is_register && modrm.reg3 == 4u
        && cpu_has_prefetchrst2(decoder->cpu_id);

#if !USE_EXTRA_OPCODES
    if (decoder->rex2_present || is_icache_prefetch || is_prefetchrst2) {
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#else
    if (decoder->rex2_present) {
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (is_icache_prefetch) {
        decoder->name_id = modrm.reg3 == 6u
            ? CDISASM_X86_NAME_PREFETCHIT1
            : CDISASM_X86_NAME_PREFETCHIT0;
        decoder->form_id = modrm.reg3 == 6u
            ? UINT16_C(2309) : UINT16_C(2308);
        return add_rm_operand(decoder, &modrm, 8u, 0)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    if (is_prefetchrst2) {
        decoder->name_id = CDISASM_X86_NAME_PREFETCHRST2;
        decoder->form_id = UINT16_C(2311);
        return add_rm_operand(decoder, &modrm, 8u, 0)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }
#endif

    if (!modrm.is_register && modrm.reg3 < 4u) {
        decoder->name_id = data_prefetch_names[modrm.reg3];
        decoder_require_caps(decoder, X86_CAP_SSE);
        return add_rm_operand(decoder, &modrm, 8u, 0)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }

    decoder->name_id = CDISASM_X86_NAME_NOP;
    decoder->form_id = modrm.is_register
        ? (cdisasm_x86_form_id)(UINT16_C(1842) + modrm.reg3)
        : (cdisasm_x86_form_id)(UINT16_C(1860) + modrm.reg3 - 4u);
    decoder_require_caps(decoder, X86_CAP_P6);
    if (!add_rm_operand(
            decoder, &modrm, decoder->operand_bits, 1)
        || !set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return add_register_operand_access(
        decoder, modrm.reg, decoder->operand_bits,
        CDISASM_OPERAND_ACCESS_READ);
}

/* 0F 1C is a deliberately overlapping allocation.  NP /0 memory is
 * CLDEMOTE only on CPUs that enumerate it; all mandatory-prefix, /1-/7, and
 * register tuples retain the architectural P6 multi-byte-NOP meaning.  APX
 * promotes the same split through REX2 map 1. */
static int decode_cldemote_nop_row(x86_decoder *decoder)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->lock_prefix) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    if (decoder->rex2_present) {
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#else
    if (decoder->rex2_present) {
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (!modrm.is_register && modrm.reg3 == 0
        && decoder->repeat_prefix == 0 && !decoder->operand_override
        && cpu_has_cldemote(decoder->cpu_id)) {
        decoder->name_id = CDISASM_X86_NAME_CLDEMOTE;
        decoder->form_id = UINT16_C(710);
        return add_rm_operand(decoder, &modrm, 8u, 0)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }
#endif

    decoder->name_id = CDISASM_X86_NAME_NOP;
    decoder->form_id = modrm.is_register
        ? UINT16_C(1855) : UINT16_C(1866);
    decoder_require_caps(decoder, X86_CAP_P6);
    if (!add_rm_operand(
            decoder, &modrm, decoder->operand_bits, 1)
        || !set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return add_register_operand_access(
        decoder, modrm.reg, decoder->operand_bits,
        CDISASM_OPERAND_ACCESS_READ);
}

/* Return -1 when the opcode is outside the legacy HRESET allocation.  Map 3
 * opcode F0 has no other legacy-prefix owner; consume its ModRM/address and
 * immediate payload before distinguishing malformed from truncated input. */
static int decode_hreset(x86_decoder *decoder, uint8_t opcode)
{
    x86_modrm modrm;
    uint64_t immediate;

    if (opcode != UINT8_C(0xf0)) {
        return -1;
    }
    if (!decode_modrm(decoder, &modrm)
        || !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    if (decoder->repeat_prefix != UINT8_C(0xf3)
        || decoder->lock_prefix || decoder->rex2_present
        || decoder->encoding.modrm != UINT8_C(0xc0)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    /* An allocated tuple on a profile without CPUID.HRESET is invalid even
     * when optional semantic lowering is compiled out. */
    if (!cpu_has_hreset(decoder->cpu_id)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_HRESET;
    decoder->form_id = UINT16_C(1319);
    decoder->groups |= CDISASM_GROUP_PRIVILEGED;
    return add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

/* Return -1 when the prefix/opcode pair is outside the Key Locker subset.
 * F3 DC is split by ModRM.mod between AESENC128KL and LOADIWKEY. */
static int decode_keylocker(x86_decoder *decoder, uint8_t opcode)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_name_id narrow_names[4] = {
        CDISASM_X86_NAME_AESENC128KL,
        CDISASM_X86_NAME_AESDEC128KL,
        CDISASM_X86_NAME_AESENC256KL,
        CDISASM_X86_NAME_AESDEC256KL
    };
    static const cdisasm_x86_form_id narrow_forms[4] = {
        UINT16_C(165), UINT16_C(157), UINT16_C(166), UINT16_C(158)
    };
    static const cdisasm_x86_name_id wide_names[4] = {
        CDISASM_X86_NAME_AESENCWIDE128KL,
        CDISASM_X86_NAME_AESDECWIDE128KL,
        CDISASM_X86_NAME_AESENCWIDE256KL,
        CDISASM_X86_NAME_AESDECWIDE256KL
    };
    static const cdisasm_x86_form_id wide_forms[4] = {
        UINT16_C(169), UINT16_C(161), UINT16_C(170), UINT16_C(162)
    };
#endif
    x86_modrm modrm;
    unsigned int selector;
    unsigned int memory_bits;
    int wide;

    if (opcode != UINT8_C(0xd8)
        && (opcode < UINT8_C(0xdc) || opcode > UINT8_C(0xdf))
        && opcode != UINT8_C(0xfa)
        && opcode != UINT8_C(0xfb)) {
        return -1;
    }
    if (decoder->repeat_prefix != UINT8_C(0xf3)
        && opcode != UINT8_C(0xfa) && opcode != UINT8_C(0xfb)) {
        return -1;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->lock_prefix || decoder->rex2_present) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    /* FA/FB have no other legacy-map-2 prefix allocation.  Consume their
     * complete structural payload before classifying a missing mandatory F3
     * as malformed; DC--DF must fall through because 66 owns AES-NI there. */
    if (decoder->repeat_prefix != UINT8_C(0xf3)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    /* An allocated tuple on a pre-Key-Locker profile is INVALID even when
     * optional opcode implementations are compiled out. */
    if (!cpu_has_keylocker(decoder->cpu_id)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0xfa) || opcode == UINT8_C(0xfb)) {
        if (!modrm.is_register) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = opcode == UINT8_C(0xfa)
            ? CDISASM_X86_NAME_ENCODEKEY128
            : CDISASM_X86_NAME_ENCODEKEY256;
        decoder->form_id = opcode == UINT8_C(0xfa)
            ? UINT16_C(1138) : UINT16_C(1139);
        decoder->prefix_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        return add_register_operand_access(
                   decoder, modrm.reg, 32u,
                   CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                   decoder, modrm.rm, 32u,
                   CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    /* F3 0F 38 DC /r with mod=3 is LOADIWKEY, not AESENC128KL. */
    if (opcode == UINT8_C(0xdc) && modrm.is_register) {
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_LOADIWKEY;
        decoder->form_id = UINT16_C(1596);
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        decoder->prefix_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        return add_vector_register_operand_access(
                   decoder, modrm.reg, 128u,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_vector_register_operand_access(
                   decoder, modrm.rm, 128u,
                   CDISASM_OPERAND_ACCESS_READ);
#endif
    }
    if (modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    wide = opcode == UINT8_C(0xd8);
    if (wide) {
        selector = modrm.reg3;
        if (selector >= 4u) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else {
        selector = (unsigned int)(opcode - UINT8_C(0xdc));
    }
    memory_bits = (selector & 2u) != 0u ? 512u : 384u;

#if !USE_EXTRA_OPCODES
    (void)memory_bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = wide ? wide_names[selector] : narrow_names[selector];
    decoder->form_id = wide ? wide_forms[selector] : narrow_forms[selector];
    decoder->prefix_flags
        |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;

    if (wide) {
        /* XMM0--XMM7 are XED SUPP operands.  The stable five-operand ABI
         * exposes the sole explicit memory operand, matching XED's display
         * contract, while retaining its exact read width and access. */
        return add_rm_operand(decoder, &modrm, memory_bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }
    return add_vector_register_operand_access(
               decoder, modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_READ_WRITE)
        && add_rm_operand(decoder, &modrm, memory_bits, 1)
        && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

/* Return -1 when the opcode is outside the controlled crypto subset. */
static int decode_modern_legacy_crypto(
    x86_decoder *decoder,
    int map_select,
    uint8_t opcode)
{
    cdisasm_x86_name_id name_id = CDISASM_X86_NAME_NONE;
    cdisasm_x86_group_id group_id = CDISASM_X86_GROUP_NONE;
    int has_imm8 = 0;
    int destination_write_only = 0;
    int implicit_xmm0 = 0;
    uint8_t required_prefix = X86_SIMD_PREFIX_NONE;
    x86_modrm modrm;
    uint64_t immediate = 0;

    if (map_select == 2) {
        if (opcode >= UINT8_C(0xdb) && opcode <= UINT8_C(0xdf)) {
            static const cdisasm_x86_name_id aes_names[5] = {
                CDISASM_X86_NAME_AESIMC,
                CDISASM_X86_NAME_AESENC,
                CDISASM_X86_NAME_AESENCLAST,
                CDISASM_X86_NAME_AESDEC,
                CDISASM_X86_NAME_AESDECLAST
            };
            name_id = aes_names[opcode - UINT8_C(0xdb)];
            group_id = CDISASM_X86_GROUP_AESNI;
            required_prefix = X86_SIMD_PREFIX_P66;
            destination_write_only = opcode == UINT8_C(0xdb);
        } else if (opcode >= UINT8_C(0xc8)
            && opcode <= UINT8_C(0xcd)) {
            static const cdisasm_x86_name_id sha_names[6] = {
                CDISASM_X86_NAME_SHA1NEXTE,
                CDISASM_X86_NAME_SHA1MSG1,
                CDISASM_X86_NAME_SHA1MSG2,
                CDISASM_X86_NAME_SHA256RNDS2,
                CDISASM_X86_NAME_SHA256MSG1,
                CDISASM_X86_NAME_SHA256MSG2
            };
            name_id = sha_names[opcode - UINT8_C(0xc8)];
            group_id = CDISASM_X86_GROUP_SHA;
            implicit_xmm0 = opcode == UINT8_C(0xcb);
        } else {
            return -1;
        }
    } else if (map_select == 3) {
        if (opcode == UINT8_C(0xdf)) {
            name_id = CDISASM_X86_NAME_AESKEYGENASSIST;
            group_id = CDISASM_X86_GROUP_AESNI;
            required_prefix = X86_SIMD_PREFIX_P66;
            has_imm8 = 1;
            destination_write_only = 1;
        } else if (opcode == UINT8_C(0x44)) {
            name_id = CDISASM_X86_NAME_PCLMULQDQ;
            group_id = CDISASM_X86_GROUP_PCLMULQDQ;
            required_prefix = X86_SIMD_PREFIX_P66;
            has_imm8 = 1;
        } else if (opcode == UINT8_C(0xcc)) {
            name_id = CDISASM_X86_NAME_SHA1RNDS4;
            group_id = CDISASM_X86_GROUP_SHA;
            has_imm8 = 1;
        } else {
            return -1;
        }
    } else {
        return -1;
    }

    if (legacy_simd_prefix(decoder) != required_prefix
        || (decoder->repeat_prefix != 0 && decoder->operand_override)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (has_imm8 && !read_immediate_value(decoder, 8, &immediate)) {
        return 0;
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)group_id;
    (void)destination_write_only;
    (void)implicit_xmm0;
    (void)immediate;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = name_id;
    decoder_require_caps(decoder, X86_CAP_SSE2);
    decoder_require_extra(decoder, group_id);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, 128u,
            destination_write_only
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ_WRITE)
        || !add_vector_rm_operand_access(
            decoder, &modrm, 128u, 128u,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    if (implicit_xmm0
        && (!add_named_register_operand(
                decoder, CDISASM_X86_REG_XMM0, 128u,
                CDISASM_OPERAND_FLAG_IMPLICIT)
            || !set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ))) {
        return 0;
    }
    return !has_imm8 || add_immediate_value(decoder, 8, immediate, 0);
#endif
}

static const x86_cet_store_descriptor *find_cet_store_descriptor(
    uint8_t opcode,
    uint8_t prefix)
{
    size_t index;

    for (index = 0;
         index < sizeof(x86_0f38_cet_store_map)
             / sizeof(x86_0f38_cet_store_map[0]);
         ++index) {
        const x86_cet_store_descriptor *descriptor =
            &x86_0f38_cet_store_map[index];

        if (descriptor->opcode == opcode && descriptor->prefix == prefix) {
            return descriptor;
        }
    }
    return NULL;
}

/* Return -1 when the opcode/prefix pair is outside legacy USER_MSR. */
static int decode_user_msr_legacy(x86_decoder *decoder, uint8_t opcode)
{
    const int is_read = decoder->repeat_prefix == UINT8_C(0xf2);
    x86_modrm modrm;

    if (opcode != UINT8_C(0xf8)
        || (!is_read && decoder->repeat_prefix != UINT8_C(0xf3))) {
        return -1;
    }
    /* F2/F3 F8 with a memory ModRM belongs to ENQCMD/ENQCMDS. */
    if (decoder->position >= decoder->code_size) {
        return decoder_fail(decoder, CDISASM_STATUS_TRUNCATED);
    }
    if ((decoder->code[decoder->position] & UINT8_C(0xc0))
        != UINT8_C(0xc0)) {
        return -1;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->mode != CDISASM_MODE_64
        || decoder->lock_prefix || decoder->rex2_present
        || !modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    (void)is_read;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = is_read
        ? CDISASM_X86_NAME_URDMSR : CDISASM_X86_NAME_UWRMSR;
    decoder->form_id = is_read ? UINT16_C(3353) : UINT16_C(3357);
    decoder_require_caps(decoder, X86_CAP_AMD64);
    if (decoder->cpu_id != CDISASM_CPU_X86) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->used_user_msr = 1;
    if (is_read) {
        return add_register_operand_access(
                decoder, modrm.rm, 64u,
                CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                decoder, modrm.reg, 64u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    return add_register_operand_access(
            decoder, modrm.reg, 64u, CDISASM_OPERAND_ACCESS_READ)
        && add_register_operand_access(
            decoder, modrm.rm, 64u, CDISASM_OPERAND_ACCESS_READ);
#endif
}

/* Return -1 when the prefix/opcode pair belongs to another 0F38 family. */
static int decode_cet_store(x86_decoder *decoder, uint8_t opcode)
{
    const x86_cet_store_descriptor *descriptor =
        find_cet_store_descriptor(opcode, legacy_simd_prefix(decoder));
    x86_modrm modrm;
    unsigned int bits;

    if (descriptor == NULL) {
        return -1;
    }
    if (decoder->lock_prefix || decoder->rex2_present) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    bits = decoder->mode == CDISASM_MODE_64 && (decoder->rex & 8u) != 0
        ? 64u
        : 32u;

#if !USE_EXTRA_OPCODES
    (void)bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = bits == 64u ? descriptor->name64 : descriptor->name32;
    decoder_require_caps(
        decoder, bits == 64u ? X86_CAP_AMD64 : X86_CAP_80386);
    decoder_require_extra(decoder, CDISASM_X86_GROUP_CET_SS);
    if (descriptor->privileged) {
        decoder->groups |= CDISASM_GROUP_PRIVILEGED;
    }
    return add_rm_operand(decoder, &modrm, bits, 1)
        && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_WRITE)
        && add_register_operand_access(
            decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ);
#endif
}

/* Return -1 when the 0F38 opcode is outside the direct-store subset. */
static int decode_direct_store(x86_decoder *decoder, uint8_t opcode)
{
    x86_modrm modrm;

    if (opcode != UINT8_C(0xf8) && opcode != UINT8_C(0xf9)) {
        return -1;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->lock_prefix || decoder->rex2_present) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (opcode == UINT8_C(0xf9)) {
        unsigned int bits;

        if (decoder->repeat_prefix != 0 || decoder->operand_override) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        bits = decoder->mode == CDISASM_MODE_64
                && (decoder->rex & UINT8_C(8)) != 0
            ? 64u
            : 32u;
#if !USE_EXTRA_OPCODES
        (void)bits;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = CDISASM_X86_NAME_MOVDIRI;
        decoder_require_caps(decoder, X86_CAP_MOVDIRI);
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                decoder, modrm.reg, bits,
                CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (decoder->repeat_prefix == UINT8_C(0xf2)
        || decoder->repeat_prefix == UINT8_C(0xf3)) {
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = decoder->repeat_prefix == UINT8_C(0xf2)
            ? CDISASM_X86_NAME_ENQCMD
            : CDISASM_X86_NAME_ENQCMDS;
        /* The generated cdisasm form catalog assigns ENQCMDS=1142 and
         * ENQCMD=1144; its intervening 1143/1145 forms are their APX-EVEX
         * siblings.  Assign the identity directly rather than relying on the
         * generated identity attachment pass. */
        decoder->form_id = decoder->name_id == CDISASM_X86_NAME_ENQCMD
            ? UINT16_C(1144) : UINT16_C(1142);
        decoder->prefix_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        decoder_require_extra(decoder, CDISASM_X86_GROUP_ENQCMD);
        if (decoder->name_id == CDISASM_X86_NAME_ENQCMDS) {
            decoder->groups |= CDISASM_GROUP_PRIVILEGED;
        }
        return add_register_operand_access(
                   decoder, modrm.reg, decoder->address_bits,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_rm_operand(decoder, &modrm, 512u, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
    }
    if (decoder->repeat_prefix != 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decoder->operand_override) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_MOVDIR64B;
    decoder_require_caps(decoder, X86_CAP_MOVDIR64B);
    return add_movdir64b_operands(decoder, &modrm);
#endif
}

/* Return -1 when the opcode belongs to another 0F 38 family. */
static int decode_modern_scalar_0f38(
    x86_decoder *decoder,
    uint8_t opcode)
{
    x86_modrm modrm;
    unsigned int bits;

    if (opcode == UINT8_C(0xf0) || opcode == UINT8_C(0xf1)) {
        /* F2 0F 38 F0/F1 are CRC32 and remain owned by the SSE4.2 map. */
        if (decoder->repeat_prefix == UINT8_C(0xf2)) {
            return -1;
        }
        if (decoder->repeat_prefix != 0 || decoder->lock_prefix
            || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (modrm.is_register) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#if !USE_EXTRA_OPCODES
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        bits = decoder->operand_bits;
        decoder->name_id = CDISASM_X86_NAME_MOVBE;
        decoder_require_extra(decoder, CDISASM_X86_GROUP_MOVBE);
        if (opcode == UINT8_C(0xf0)) {
            return add_register_operand_access(
                       decoder, modrm.reg, bits,
                       CDISASM_OPERAND_ACCESS_WRITE)
                && add_rm_operand(decoder, &modrm, bits, 1)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_WRITE)
            && add_register_operand_access(
                   decoder, modrm.reg, bits,
                   CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (opcode == UINT8_C(0xf6)) {
        const int is_adcx = decoder->operand_override
            && decoder->repeat_prefix == 0;
        const int is_adox = decoder->repeat_prefix == UINT8_C(0xf3);

        if ((!is_adcx && !is_adox) || decoder->lock_prefix
            || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        bits = decoder->mode == CDISASM_MODE_64
                && (decoder->rex & UINT8_C(8)) != 0
            ? 64u
            : 32u;
#if !USE_EXTRA_OPCODES
        (void)is_adcx;
        (void)is_adox;
        (void)bits;
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        decoder->name_id = is_adcx
            ? CDISASM_X86_NAME_ADCX
            : CDISASM_X86_NAME_ADOX;
        decoder_require_extra(decoder, CDISASM_X86_GROUP_ADX);
        return add_register_operand_access(
                   decoder, modrm.reg, bits,
                   CDISASM_OPERAND_ACCESS_READ_WRITE)
            && add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
    }

    if (opcode != UINT8_C(0x82)) {
        return -1;
    }
    if (!decoder->operand_override || decoder->repeat_prefix != 0
        || decoder->lock_prefix || decoder->rex2_present) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    bits = decoder->mode == CDISASM_MODE_64 ? 64u : 32u;
#if !USE_EXTRA_OPCODES
    (void)bits;
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_INVPCID;
    decoder->groups |= CDISASM_GROUP_PRIVILEGED;
    decoder_require_extra(decoder, CDISASM_X86_GROUP_INVPCID);
    return add_register_operand_access(
               decoder, modrm.reg, bits,
               CDISASM_OPERAND_ACCESS_READ)
        && add_rm_operand(decoder, &modrm, 128u, 1)
        && set_last_operand_access(decoder, CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_rao_int(x86_decoder *decoder, uint8_t opcode)
{
    x86_modrm modrm;

    if (opcode != UINT8_C(0xfc)) {
        return -1;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register || decoder->lock_prefix || decoder->rex2_present) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    {
        cdisasm_x86_name_id name_id;
        unsigned int bits = decoder->mode == CDISASM_MODE_64
                && (decoder->rex & UINT8_C(8)) != 0
            ? 64u
            : 32u;

        /* No named profile in the pinned XED baseline advertises RAO-INT.
         * The unrestricted profile remains the explicit forward-compatible
         * route until a documented processor profile gains the feature. */
        if (decoder->cpu_id != CDISASM_CPU_X86) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (decoder->repeat_prefix == UINT8_C(0xf2)) {
            name_id = CDISASM_X86_NAME_AOR;
        } else if (decoder->repeat_prefix == UINT8_C(0xf3)) {
            name_id = CDISASM_X86_NAME_AXOR;
        } else if (decoder->operand_override) {
            name_id = CDISASM_X86_NAME_AAND;
        } else {
            name_id = CDISASM_X86_NAME_AADD;
        }

        decoder->name_id = name_id;
        decoder->used_rao_int = 1;
        return add_rm_operand(decoder, &modrm, bits, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_READ_WRITE)
            && add_register_operand_access(
                   decoder, modrm.reg, bits, CDISASM_OPERAND_ACCESS_READ);
    }
#endif
}

static int decode_movntdqa_legacy(
    x86_decoder *decoder,
    uint8_t opcode)
{
    x86_modrm modrm;

    if (opcode != UINT8_C(0x2a)) {
        return -1;
    }

    /* MOVNTDQA is the complete legacy 66 0F 38 2A memory-only row.  Decode
     * its address before prefix/register validation to preserve truncation
     * precedence for otherwise reserved controls. */
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register || decoder->lock_prefix
        || decoder->repeat_prefix != 0 || !decoder->operand_override) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decoder_has_caps(decoder, X86_CAP_SSE41)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_MOVNTDQA;
    decoder->form_id = UINT16_C(1690);
    decoder_require_caps(decoder, X86_CAP_SSE41);
    return add_vector_register_operand_access(
               decoder, modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
               decoder, &modrm, 128u, 128u,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_lddqu_legacy(
    x86_decoder *decoder,
    uint8_t opcode)
{
    x86_modrm modrm;

    if (opcode != UINT8_C(0xf0)) {
        return -1;
    }

    /* LDDQU owns the complete legacy 0F F0 row.  F2 is mandatory while 66
     * is explicitly ignored by the architecture.  Decode the address first
     * so malformed memory encodings retain TRUNCATED precedence. */
    if (decoder->rex2_present) {
        decoder->modrm_reg_high = 0;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (modrm.is_register || decoder->lock_prefix
        || decoder->repeat_prefix != UINT8_C(0xf2)
        || (decoder->rex2_present
            && !cpu_has_apx_f(decoder->cpu_id))) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decoder_has_caps(decoder, X86_CAP_SSE3)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    decoder->name_id = CDISASM_X86_NAME_LDDQU;
    decoder->form_id = UINT16_C(1574);
    decoder_require_caps(decoder, X86_CAP_SSE3);
    return add_vector_register_operand_access(
               decoder, modrm.reg, 128u,
               CDISASM_OPERAND_ACCESS_WRITE)
        && add_vector_rm_operand_access(
               decoder, &modrm, 128u, 128u,
               CDISASM_OPERAND_ACCESS_READ);
#endif
}

static int decode_gfni_legacy(
    x86_decoder *decoder,
    uint8_t map_select,
    uint8_t opcode)
{
    const int affine = map_select == UINT8_C(3)
        && (opcode == UINT8_C(0xce) || opcode == UINT8_C(0xcf));
    const int multiply = map_select == UINT8_C(2)
        && opcode == UINT8_C(0xcf);
    x86_modrm modrm;
    uint64_t immediate = 0u;

    if (!affine && !multiply) {
        return -1;
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (affine && !read_immediate_value(decoder, 8u, &immediate)) {
        return 0;
    }
    /* Mandatory 66 selects all six legacy forms.  REX.W is explicitly
     * ignored, while repeat and LOCK selectors are reserved. */
    if (!decoder->operand_override || decoder->repeat_prefix != 0u
        || decoder->lock_prefix) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)immediate;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (multiply) {
        decoder->name_id = CDISASM_X86_NAME_GF2P8MULB;
        decoder->form_id = (cdisasm_x86_form_id)(
            UINT16_C(1312) + (modrm.is_register ? 1u : 0u));
    } else if (opcode == UINT8_C(0xcf)) {
        decoder->name_id = CDISASM_X86_NAME_GF2P8AFFINEINVQB;
        decoder->form_id = (cdisasm_x86_form_id)(
            UINT16_C(1308) + (modrm.is_register ? 1u : 0u));
    } else {
        decoder->name_id = CDISASM_X86_NAME_GF2P8AFFINEQB;
        decoder->form_id = (cdisasm_x86_form_id)(
            UINT16_C(1310) + (modrm.is_register ? 1u : 0u));
    }
    decoder_require_extra(decoder, CDISASM_X86_GROUP_GFNI);
    if (!add_vector_register_operand_access(
            decoder, modrm.reg, 128u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        || !add_vector_rm_operand_access(
            decoder, &modrm, 128u, 128u,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return !affine
        || add_immediate_value(decoder, 8u, immediate, 0);
#endif
}

static int decode_three_byte_map(
    x86_decoder *decoder,
    const x86_opcode_descriptor map[256])
{
    uint8_t opcode;
    const x86_opcode_descriptor *descriptor;
    x86_modrm modrm;
    unsigned int bits = decoder->mode == CDISASM_MODE_64 ? 64u : 32u;

    if (!read_u8(decoder, &opcode)) {
        return 0;
    }
    ++decoder->encoding.opcode_size;
    {
        const uint8_t map_select = map == x86_0f38_map ? UINT8_C(2)
            : map == x86_0f3a_map ? UINT8_C(3) : UINT8_C(0);
        const int gfni_result = decode_gfni_legacy(
            decoder, map_select, opcode);

        if (gfni_result >= 0) {
            return gfni_result;
        }
    }
    if (map == x86_0f38_map) {
        int direct_result = decode_movntdqa_legacy(decoder, opcode);
        if (direct_result >= 0) {
            return direct_result;
        }
        direct_result = decode_user_msr_legacy(decoder, opcode);
        if (direct_result >= 0) {
            return direct_result;
        }
        direct_result = decode_keylocker(decoder, opcode);
        if (direct_result >= 0) {
            return direct_result;
        }
        direct_result = decode_rao_int(decoder, opcode);
        if (direct_result >= 0) {
            return direct_result;
        }
        direct_result = decode_direct_store(decoder, opcode);
        if (direct_result >= 0) {
            return direct_result;
        }
        int cet_result = decode_cet_store(decoder, opcode);
        if (cet_result >= 0) {
            return cet_result;
        }
        int modern_result = decode_modern_legacy_crypto(decoder, 2, opcode);
        if (modern_result >= 0) {
            return modern_result;
        }
        modern_result = decode_modern_scalar_0f38(decoder, opcode);
        if (modern_result >= 0) {
            return modern_result;
        }
    } else if (map == x86_0f3a_map) {
        int modern_result = decode_hreset(decoder, opcode);
        if (modern_result >= 0) {
            return modern_result;
        }
        modern_result = decode_modern_legacy_crypto(decoder, 3, opcode);
        if (modern_result >= 0) {
            return modern_result;
        }
    }
    if (map == x86_0f38_map) {
        int simd_result = decode_legacy_simd_map(
            decoder,
            x86_0f38_simd_map,
            sizeof(x86_0f38_simd_map) / sizeof(x86_0f38_simd_map[0]),
            opcode);
        if (simd_result >= 0) {
            return simd_result;
        }
    } else if (map == x86_0f3a_map) {
        int simd_result = decode_legacy_simd_map(
            decoder,
            x86_0f3a_simd_map,
            sizeof(x86_0f3a_simd_map) / sizeof(x86_0f3a_simd_map[0]),
            opcode);
        if (simd_result >= 0) {
            return simd_result;
        }
    }
    descriptor = &map[opcode];
    decoder->groups |= descriptor->groups;

    switch ((x86_decode_form)descriptor->form) {
        case X86_DECODE_FORM_UNSUPPORTED:
            return decoder_fail(
                decoder,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        case X86_DECODE_FORM_INVALID:
            return decoder_fail(
                decoder,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        case X86_DECODE_FORM_VMX_INVALIDATE:
            if (!decoder->operand_override || decoder->repeat_prefix != 0) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            if (!decode_modrm(decoder, &modrm)) {
                return 0;
            }
            if (modrm.is_register) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            return add_register_operand(decoder, modrm.reg, bits)
                && add_rm_operand(
                    decoder,
                    &modrm,
                    descriptor->argument,
                    1);
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
}


static int add_mmx_rm_operand(
    x86_decoder *decoder,
    const x86_modrm *modrm)
{
    if (modrm->is_register) {
        cdisasm_x86_reg_id register_id = mmx_id(modrm->rm3);

        if (register_id == CDISASM_REG_NONE) {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        return add_named_register_operand(decoder, register_id, 64, 0);
    }
    return add_rm_operand(decoder, modrm, 64, 1);
}

static int add_xmm_register_operand(
    x86_decoder *decoder,
    unsigned int index)
{
    cdisasm_x86_reg_id register_id = xmm_id(index);

    if (register_id == CDISASM_REG_NONE) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    return add_named_register_operand(decoder, register_id, 128, 0);
}

static int add_xmm_rm_operand(
    x86_decoder *decoder,
    const x86_modrm *modrm,
    unsigned int memory_bits)
{
    if (modrm->is_register) {
        return add_xmm_register_operand(decoder, modrm->rm);
    }
    return add_rm_operand(decoder, modrm, memory_bits, 1);
}

static int add_gpr_rm_scalar_operand(
    x86_decoder *decoder,
    const x86_modrm *modrm,
    unsigned int memory_bits)
{
    if (modrm->is_register) {
        return add_register_operand(decoder, modrm->rm, 32);
    }
    return add_rm_operand(decoder, modrm, memory_bits, 1);
}

static uint64_t simd_feature_capability(uint8_t feature)
{
    switch ((x86_simd_feature)feature) {
        case X86_SIMD_FEATURE_SSE:
            return X86_CAP_SSE;
        case X86_SIMD_FEATURE_SSE2:
            return X86_CAP_SSE2;
        case X86_SIMD_FEATURE_SSE3:
            return X86_CAP_SSE3;
        case X86_SIMD_FEATURE_SSSE3:
            return X86_CAP_SSSE3;
        case X86_SIMD_FEATURE_SSE41:
            return X86_CAP_SSE41;
        case X86_SIMD_FEATURE_SSE4A:
            return X86_CAP_SSE4A;
        case X86_SIMD_FEATURE_SSE42:
            return X86_CAP_SSE42;
        case X86_SIMD_FEATURE_MMX:
            return X86_CAP_MMX;
        default:
            return 0;
    }
}

static uint8_t legacy_simd_prefix(const x86_decoder *decoder)
{
    if (decoder->repeat_prefix == 0xf3) {
        return X86_SIMD_PREFIX_PF3;
    }
    if (decoder->repeat_prefix == 0xf2) {
        return X86_SIMD_PREFIX_PF2;
    }
    return decoder->operand_override
        ? X86_SIMD_PREFIX_P66
        : X86_SIMD_PREFIX_NONE;
}

static const x86_simd_descriptor *find_legacy_simd_descriptor(
    const x86_simd_descriptor *map,
    size_t count,
    uint8_t opcode,
    uint8_t prefix)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        if (map[index].opcode == opcode && map[index].prefix == prefix) {
            return &map[index];
        }
    }
    return NULL;
}

static int simd_modrm_matches_flags(
    x86_decoder *decoder,
    const x86_simd_descriptor *descriptor,
    const x86_modrm *modrm)
{
    if ((descriptor->flags & X86_SIMD_FLAG_MEMORY_ONLY) != 0
        && modrm->is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if ((descriptor->flags & X86_SIMD_FLAG_REGISTER_ONLY) != 0
        && !modrm->is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    return 1;
}

/*
 * Return -1 when this prefix/opcode combination is not in the SIMD table,
 * zero on a decode error, and one after decoding a table entry.
 */
static int decode_legacy_simd_map(
    x86_decoder *decoder,
    const x86_simd_descriptor *map,
    size_t count,
    uint8_t opcode)
{
    const x86_simd_descriptor *descriptor = find_legacy_simd_descriptor(
        map,
        count,
        opcode,
        legacy_simd_prefix(decoder));
    x86_modrm modrm;
    uint64_t capability;
    unsigned int gpr_bits;

    if (descriptor == NULL) {
        return -1;
    }
    capability = simd_feature_capability(descriptor->feature);
    if (capability == 0) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }

    /* 66 is a second mandatory-prefix selector except for CRC32's word form
     * and the 0F 78/79 INSERTQ collisions, where F2 remains the refining
     * selector and XED accepts 66 in either prefix order. */
    if (decoder->repeat_prefix != 0
        && decoder->operand_override
        && descriptor->form != X86_SIMD_FORM_CRC32
        && !((opcode == UINT8_C(0x78) || opcode == UINT8_C(0x79))
            && descriptor->name_id == CDISASM_X86_NAME_INSERTQ)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (!simd_modrm_matches_flags(decoder, descriptor, &modrm)) {
        return 0;
    }
    if (opcode == UINT8_C(0x78)
        && descriptor->name_id == CDISASM_X86_NAME_EXTRQ
        && modrm.reg3 != 0u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    decoder_require_caps(decoder, capability);
    decoder->name_id = descriptor->name_id;
    if (descriptor->name_id == CDISASM_X86_NAME_PCMPESTRI) {
        decoder->form_id = (decoder->rex & 8u) != 0
            ? (modrm.is_register ? UINT16_C(2058) : UINT16_C(2057))
            : (modrm.is_register ? UINT16_C(2060) : UINT16_C(2059));
    } else if (descriptor->name_id == CDISASM_X86_NAME_PCMPESTRM) {
        decoder->form_id = (decoder->rex & 8u) != 0
            ? (modrm.is_register ? UINT16_C(2062) : UINT16_C(2061))
            : (modrm.is_register ? UINT16_C(2064) : UINT16_C(2063));
    } else if (descriptor->name_id == CDISASM_X86_NAME_PCMPISTRI) {
        decoder->form_id = decoder->mode == CDISASM_MODE_64
            ? (modrm.is_register ? UINT16_C(2080) : UINT16_C(2079))
            : (modrm.is_register ? UINT16_C(2082) : UINT16_C(2081));
    } else if (descriptor->name_id == CDISASM_X86_NAME_PCMPISTRM) {
        decoder->form_id = modrm.is_register
            ? UINT16_C(2084)
            : UINT16_C(2083);
    }
    gpr_bits = decoder->mode == CDISASM_MODE_64 && (decoder->rex & 8u) != 0
        ? 64u
        : 32u;
    if ((descriptor->form == X86_SIMD_FORM_MMX_GPR_RM
            || descriptor->form == X86_SIMD_FORM_GPR_RM_MMX)
        && gpr_bits == 64u) {
        decoder->name_id = CDISASM_X86_NAME_MOVQ;
    }

    switch ((x86_simd_form)descriptor->form) {
        case X86_SIMD_FORM_XMM_RM:
            return add_xmm_register_operand(decoder, modrm.reg)
                && add_xmm_rm_operand(
                    decoder,
                    &modrm,
                    descriptor->memory_bits);

        case X86_SIMD_FORM_XMM_RM_IMPLICIT_XMM0:
            return add_xmm_register_operand(decoder, modrm.reg)
                && add_xmm_rm_operand(
                    decoder,
                    &modrm,
                    descriptor->memory_bits)
                && add_named_register_operand(
                    decoder,
                    CDISASM_X86_REG_XMM0,
                    128,
                    CDISASM_OPERAND_FLAG_IMPLICIT);

        case X86_SIMD_FORM_RM_XMM:
            return add_xmm_rm_operand(
                    decoder,
                    &modrm,
                    descriptor->memory_bits)
                && add_xmm_register_operand(decoder, modrm.reg);

        case X86_SIMD_FORM_XMM_RM_IMM8:
            return add_xmm_register_operand(decoder, modrm.reg)
                && add_xmm_rm_operand(
                    decoder,
                    &modrm,
                    descriptor->memory_bits)
                && add_immediate_operand(decoder, 8, 0);

        case X86_SIMD_FORM_XMM_RM_IMM8_IMM8:
            return add_xmm_register_operand(decoder, modrm.reg)
                && add_xmm_rm_operand(
                    decoder,
                    &modrm,
                    descriptor->memory_bits)
                && add_immediate_operand(decoder, 8, 0)
                && add_immediate_operand(decoder, 8, 0);

        case X86_SIMD_FORM_XMM_RM_ONLY_IMM8_IMM8:
            return add_xmm_register_operand(decoder, modrm.rm)
                && add_immediate_operand(decoder, 8, 0)
                && add_immediate_operand(decoder, 8, 0);

        case X86_SIMD_FORM_GPR_XMM:
            /* MOVMSKPS/MOVMSKPD/PMOVMSKB always write r32; REX.W is ignored. */
            return add_register_operand(decoder, modrm.reg, 32)
                && add_xmm_rm_operand(decoder, &modrm, 128);

        case X86_SIMD_FORM_XMM_GPR_RM:
            return add_xmm_register_operand(decoder, modrm.reg)
                && add_rm_operand(decoder, &modrm, gpr_bits, 1);

        case X86_SIMD_FORM_GPR_XMM_RM:
            return add_register_operand(decoder, modrm.reg, gpr_bits)
                && add_xmm_rm_operand(
                    decoder,
                    &modrm,
                    descriptor->memory_bits);

        case X86_SIMD_FORM_XMM_MMX_RM:
            return add_xmm_register_operand(decoder, modrm.reg)
                && add_mmx_rm_operand(decoder, &modrm);

        case X86_SIMD_FORM_MMX_XMM_RM: {
            cdisasm_x86_reg_id destination = mmx_id(modrm.reg3);

            if (destination == CDISASM_REG_NONE) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_named_register_operand(decoder, destination, 64, 0)
                && add_xmm_rm_operand(
                    decoder,
                    &modrm,
                    descriptor->memory_bits);
        }

        case X86_SIMD_FORM_MMX_RM: {
            cdisasm_x86_reg_id destination = mmx_id(modrm.reg3);

            if (destination == CDISASM_REG_NONE) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_named_register_operand(decoder, destination, 64, 0)
                && add_mmx_rm_operand(decoder, &modrm);
        }

        case X86_SIMD_FORM_RM_MMX: {
            cdisasm_x86_reg_id source = mmx_id(modrm.reg3);

            if (source == CDISASM_REG_NONE) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_mmx_rm_operand(decoder, &modrm)
                && add_named_register_operand(decoder, source, 64, 0);
        }

        case X86_SIMD_FORM_MMX_RM_IMM8: {
            cdisasm_x86_reg_id destination = mmx_id(modrm.reg3);

            if (destination == CDISASM_REG_NONE) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_named_register_operand(decoder, destination, 64, 0)
                && add_mmx_rm_operand(decoder, &modrm)
                && add_immediate_operand(decoder, 8, 0);
        }

        case X86_SIMD_FORM_GPR_MMX_IMM8:
            if (!modrm.is_register) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_register_operand(decoder, modrm.reg, 32)
                && add_mmx_rm_operand(decoder, &modrm)
                && add_immediate_operand(decoder, 8, 0);

        case X86_SIMD_FORM_MMX_GPR_RM_IMM8: {
            cdisasm_x86_reg_id destination = mmx_id(modrm.reg3);

            if (destination == CDISASM_REG_NONE) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_named_register_operand(decoder, destination, 64, 0)
                && add_gpr_rm_scalar_operand(
                    decoder,
                    &modrm,
                    descriptor->memory_bits)
                && add_immediate_operand(decoder, 8, 0);
        }

        case X86_SIMD_FORM_MMX_GPR_RM: {
            cdisasm_x86_reg_id destination = mmx_id(modrm.reg3);

            if (destination == CDISASM_REG_NONE) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_named_register_operand(decoder, destination, 64, 0)
                && (modrm.is_register
                    ? add_register_operand(decoder, modrm.rm, gpr_bits)
                    : add_rm_operand(decoder, &modrm, gpr_bits, 1));
        }

        case X86_SIMD_FORM_GPR_RM_MMX: {
            cdisasm_x86_reg_id source = mmx_id(modrm.reg3);

            if (source == CDISASM_REG_NONE) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return (modrm.is_register
                    ? add_register_operand(decoder, modrm.rm, gpr_bits)
                    : add_rm_operand(decoder, &modrm, gpr_bits, 1))
                && add_named_register_operand(decoder, source, 64, 0);
        }

        case X86_SIMD_FORM_GPR_XMM_IMM8:
            if (!modrm.is_register) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_register_operand(decoder, modrm.reg, 32)
                && add_xmm_rm_operand(decoder, &modrm, 128)
                && add_immediate_operand(decoder, 8, 0);

        case X86_SIMD_FORM_XMM_GPR_RM_IMM8:
            if ((decoder->rex & 8u) != 0
                && descriptor->name_id == CDISASM_X86_NAME_PINSRD) {
                decoder->name_id = CDISASM_X86_NAME_PINSRQ;
                decoder->form_id = modrm.is_register
                    ? UINT16_C(2185)
                    : UINT16_C(2186);
                return add_xmm_register_operand(decoder, modrm.reg)
                    && (modrm.is_register
                        ? add_register_operand(decoder, modrm.rm, 64)
                        : add_rm_operand(decoder, &modrm, 64, 1))
                    && add_immediate_operand(decoder, 8, 0);
            }
            if (descriptor->name_id == CDISASM_X86_NAME_PINSRD) {
                decoder->form_id = modrm.is_register
                    ? UINT16_C(2183)
                    : UINT16_C(2184);
            }
            return add_xmm_register_operand(decoder, modrm.reg)
                && add_gpr_rm_scalar_operand(
                    decoder,
                    &modrm,
                    descriptor->memory_bits)
                && add_immediate_operand(decoder, 8, 0);

        case X86_SIMD_FORM_RM_XMM_IMM8:
            if ((decoder->rex & 8u) != 0
                && descriptor->name_id == CDISASM_X86_NAME_PEXTRD) {
                decoder->name_id = CDISASM_X86_NAME_PEXTRQ;
                decoder->form_id = modrm.is_register
                    ? UINT16_C(2099)
                    : UINT16_C(2100);
                if (modrm.is_register) {
                    if (!add_register_operand(decoder, modrm.rm, 64)) {
                        return 0;
                    }
                } else if (!add_rm_operand(decoder, &modrm, 64, 1)) {
                    return 0;
                }
                return add_xmm_register_operand(decoder, modrm.reg)
                    && add_immediate_operand(decoder, 8, 0);
            }
            if (descriptor->name_id == CDISASM_X86_NAME_PEXTRW) {
                decoder->form_id = modrm.is_register
                    ? UINT16_C(2103)
                    : UINT16_C(2104);
            } else if (descriptor->name_id == CDISASM_X86_NAME_PEXTRD) {
                decoder->form_id = modrm.is_register
                    ? UINT16_C(2097)
                    : UINT16_C(2098);
            }
            if (modrm.is_register) {
                if (!add_register_operand(decoder, modrm.rm, 32)) {
                    return 0;
                }
            } else if (!add_rm_operand(
                decoder,
                &modrm,
                descriptor->memory_bits,
                1)) {
                return 0;
            }
            return add_xmm_register_operand(decoder, modrm.reg)
                && add_immediate_operand(decoder, 8, 0);

        case X86_SIMD_FORM_MMX_REG_RM: {
            cdisasm_x86_reg_id destination = mmx_id(modrm.reg3);

            if (!modrm.is_register || destination == CDISASM_REG_NONE) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return add_named_register_operand(decoder, destination, 64, 0)
                && add_mmx_rm_operand(decoder, &modrm);
        }

        case X86_SIMD_FORM_MOVLPS:
        case X86_SIMD_FORM_MOVHPS:
            if (modrm.is_register) {
                decoder->name_id = descriptor->form == X86_SIMD_FORM_MOVLPS
                    ? CDISASM_X86_NAME_MOVHLPS
                    : CDISASM_X86_NAME_MOVLHPS;
            }
            return add_xmm_register_operand(decoder, modrm.reg)
                && add_xmm_rm_operand(decoder, &modrm, 64);

        case X86_SIMD_FORM_MXCSR:
            if (!modrm.is_register && modrm.reg3 == 2) {
                decoder->name_id = CDISASM_X86_NAME_LDMXCSR;
                return add_rm_operand(decoder, &modrm, 32, 1);
            }
            if (!modrm.is_register && modrm.reg3 == 3) {
                decoder->name_id = CDISASM_X86_NAME_STMXCSR;
                return add_rm_operand(decoder, &modrm, 32, 1);
            }
            if (decoder->encoding.modrm == 0xf8) {
                decoder->name_id = CDISASM_X86_NAME_SFENCE;
                return 1;
            }
            return decoder_fail(
                decoder,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        case X86_SIMD_FORM_PREFETCH: {
            static const cdisasm_x86_name_id prefetch_names[4] = {
                CDISASM_X86_NAME_PREFETCHNTA,
                CDISASM_X86_NAME_PREFETCHT0,
                CDISASM_X86_NAME_PREFETCHT1,
                CDISASM_X86_NAME_PREFETCHT2
            };

            if (modrm.is_register) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            if (modrm.reg3 >= 4) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
            decoder->name_id = prefetch_names[modrm.reg3];
            return add_rm_operand(decoder, &modrm, 8, 0);
        }

        case X86_SIMD_FORM_CRC32: {
            unsigned int source_bits;

            if (descriptor->memory_bits != 0) {
                source_bits = descriptor->memory_bits;
            } else if ((decoder->rex & 8u) != 0) {
                source_bits = 64;
            } else {
                source_bits = decoder->operand_override ? 16u : 32u;
            }
            return add_register_operand(decoder, modrm.reg, gpr_bits)
                && add_rm_operand(decoder, &modrm, source_bits, 1);
        }

        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
}

static int decode_3dnow(x86_decoder *decoder)
{
    x86_modrm modrm;
    uint8_t selector;
    const x86_opcode_descriptor *descriptor;
    cdisasm_x86_reg_id destination;

    /* The final byte selects the instruction after the complete ModRM/SIB
     * memory operand, so it is part of the opcode rather than an operand. */
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->encoding.selector_offset = (uint8_t)decoder->position;
    if (!read_u8(decoder, &selector)) {
        return 0;
    }
    descriptor = &x86_3dnow_map[selector];
    decoder->groups |= descriptor->groups;
    if ((x86_decode_form)descriptor->form
        == X86_DECODE_FORM_UNSUPPORTED) {
        return decoder_fail(
            decoder,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    if ((x86_decode_form)descriptor->form
        != X86_DECODE_FORM_3DNOW_SELECTOR) {
        return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }

    destination = mmx_id(modrm.reg3);
    if (destination == CDISASM_REG_NONE) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->name_id = descriptor->name_id;
    return add_named_register_operand(decoder, destination, 64, 0)
        && add_mmx_rm_operand(decoder, &modrm);
}

static int decode_3dnow_prefetch(x86_decoder *decoder)
{
    x86_modrm modrm;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->lock_prefix) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!modrm.is_register && modrm.reg3 == 2u
        && !cpu_has_prefetchwt1(decoder->cpu_id)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#if !USE_EXTRA_OPCODES
    if (decoder->rex2_present
        || (!modrm.is_register && modrm.reg3 == 2u)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#else
    if (decoder->rex2_present) {
        decoder_require_caps(decoder, X86_CAP_AMD64);
        decoder_require_extra(decoder, CDISASM_X86_GROUP_APX_F);
    }
    if (!modrm.is_register && modrm.reg3 == 2u) {
        decoder->name_id = CDISASM_X86_NAME_PREFETCHWT1;
        decoder->form_id = UINT16_C(2315);
        return add_rm_operand(decoder, &modrm, 8u, 0)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
    }
#endif
    if (modrm.is_register && modrm.reg3 == 2u) {
        decoder->name_id = CDISASM_X86_NAME_NOP;
        decoder->form_id = UINT16_C(1851);
        decoder_require_caps(decoder, X86_CAP_P6);
        return add_register_operand_access(
                   decoder, modrm.rm, decoder->operand_bits,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_register_operand_access(
                   decoder, modrm.reg, decoder->operand_bits,
                   CDISASM_OPERAND_ACCESS_READ);
    }
    /* AMD allocated both /1 and /3 to PREFETCHW.  Keep /2 owned by
     * PREFETCHWT1 above; /4--/7 are PREFETCH_RESERVED catalog forms. */
    if (modrm.reg3 > 3u || modrm.reg3 == 2u) {
#if USE_EXTRA_OPCODES
        /* XED names the unallocated memory /4-/7 encodings explicitly.
         * Their architectural operand is an unsized prefetch address, not a
         * 512-bit vector; retain the catalog ID and use VARIABLE size so the
         * formatter emits the canonical `ptr` spelling. */
        if (!modrm.is_register && modrm.reg3 >= 4u
            && decoder_has_extra(decoder, CDISASM_X86_GROUP_PREFETCH_NOP)) {
            decoder->name_id = CDISASM_X86_NAME_PREFETCH_RESERVED;
            decoder_require_extra(
                decoder, CDISASM_X86_GROUP_PREFETCH_NOP);
            if (!add_rm_operand(decoder, &modrm, 512u, 1)) {
                return 0;
            }
            decoder->operand[decoder->operand_count - 1u].size =
                CDISASM_X86_OPERAND_SIZE_VARIABLE;
            return set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ);
        }
#endif
        return decoder_fail(decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    if (modrm.is_register) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder->name_id = modrm.reg3 == 0
        ? CDISASM_X86_NAME_PREFETCH
        : CDISASM_X86_NAME_PREFETCHW;
    return add_rm_operand(decoder, &modrm, 8, 1);
}

/* Decode the complete 0F 1A/1B MPX row.  In the architecturally unprefixed
 * register form these bytes remain multi-byte NOPs; every MPX interpretation
 * is independently gated by the retired-but-stable MPX feature group. */
static int decode_mpx_row(x86_decoder *decoder, uint8_t opcode)
{
    x86_modrm modrm;
    uint8_t selector;

    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    if (decoder->lock_prefix || decoder->rex2_present) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    selector = decoder->repeat_prefix != 0
        ? decoder->repeat_prefix
        : (decoder->operand_override ? UINT8_C(0x66) : 0);
    if (decoder->repeat_prefix != 0 && decoder->operand_override) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    if (modrm.is_register
        && (selector == 0
            || (selector == UINT8_C(0xf3)
                && opcode == UINT8_C(0x1b)))) {
        decoder->name_id = CDISASM_X86_NAME_NOP;
        decoder_require_caps(decoder, X86_CAP_P6);
        return add_register_operand_access(
                   decoder, modrm.rm, decoder->operand_bits,
                   CDISASM_OPERAND_ACCESS_READ)
            && add_register_operand_access(
                   decoder, modrm.reg, decoder->operand_bits,
                   CDISASM_OPERAND_ACCESS_READ);
    }

#if !USE_EXTRA_OPCODES
    (void)opcode;
    (void)selector;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (decoder->address_bits == 16u || modrm.reg >= 4u) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    decoder_require_extra(decoder, CDISASM_X86_GROUP_MPX);

    if (selector == UINT8_C(0xf3)) {
        if (opcode == UINT8_C(0x1a)) {
            decoder->name_id = CDISASM_X86_NAME_BNDCL;
        } else if (!modrm.is_register) {
            decoder->name_id = CDISASM_X86_NAME_BNDMK;
        } else {
            return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (modrm.is_register) {
            return add_bnd_register_operand_access(
                       decoder, modrm.reg,
                       CDISASM_OPERAND_ACCESS_READ)
                && add_register_operand_access(
                       decoder, modrm.rm, decoder->address_bits,
                       CDISASM_OPERAND_ACCESS_READ);
        }
        if (modrm.rip_relative
            || !add_bnd_register_operand_access(
                decoder, modrm.reg,
                decoder->name_id == CDISASM_X86_NAME_BNDMK
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ)
            || !add_rm_operand(decoder, &modrm, 8u, 1)) {
            return decoder->error == CDISASM_STATUS_OK
                ? decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION)
                : 0;
        }
        decoder->operand[decoder->operand_count - 1u].flags |=
            CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        return set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ);
    }

    if (selector == UINT8_C(0xf2)) {
        decoder->name_id = opcode == UINT8_C(0x1a)
            ? CDISASM_X86_NAME_BNDCU
            : CDISASM_X86_NAME_BNDCN;
        if (modrm.is_register) {
            return add_bnd_register_operand_access(
                       decoder, modrm.reg,
                       CDISASM_OPERAND_ACCESS_READ)
                && add_register_operand_access(
                       decoder, modrm.rm, decoder->address_bits,
                       CDISASM_OPERAND_ACCESS_READ);
        }
        if (modrm.rip_relative
            || !add_bnd_register_operand_access(
                decoder, modrm.reg, CDISASM_OPERAND_ACCESS_READ)
            || !add_rm_operand(decoder, &modrm, 8u, 1)) {
            return decoder->error == CDISASM_STATUS_OK
                ? decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION)
                : 0;
        }
        decoder->operand[decoder->operand_count - 1u].flags |=
            CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        return set_last_operand_access(
            decoder, CDISASM_OPERAND_ACCESS_READ);
    }

    if (selector == UINT8_C(0x66)) {
        const unsigned int memory_bits =
            decoder->mode == CDISASM_MODE_64 ? 128u : 64u;

        decoder->name_id = CDISASM_X86_NAME_BNDMOV;
        if (opcode == UINT8_C(0x1a)) {
            if (!add_bnd_register_operand_access(
                    decoder, modrm.reg, CDISASM_OPERAND_ACCESS_WRITE)) {
                return 0;
            }
            if (modrm.is_register) {
                return add_bnd_register_operand_access(
                    decoder, modrm.rm, CDISASM_OPERAND_ACCESS_READ);
            }
            return add_rm_operand(decoder, &modrm, memory_bits, 1)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        if (modrm.is_register) {
            return add_bnd_register_operand_access(
                       decoder, modrm.rm,
                       CDISASM_OPERAND_ACCESS_WRITE)
                && add_bnd_register_operand_access(
                       decoder, modrm.reg,
                       CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, memory_bits, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_WRITE)
            && add_bnd_register_operand_access(
                   decoder, modrm.reg, CDISASM_OPERAND_ACCESS_READ);
    }

    if (selector == 0 && !modrm.is_register) {
        const unsigned int memory_bits =
            decoder->mode == CDISASM_MODE_64 ? 192u : 96u;

        if (modrm.rip_relative) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = opcode == UINT8_C(0x1a)
            ? CDISASM_X86_NAME_BNDLDX
            : CDISASM_X86_NAME_BNDSTX;
        if (opcode == UINT8_C(0x1a)) {
            return add_bnd_register_operand_access(
                       decoder, modrm.reg,
                       CDISASM_OPERAND_ACCESS_WRITE)
                && add_rm_operand(decoder, &modrm, memory_bits, 1)
                && set_last_operand_access(
                       decoder, CDISASM_OPERAND_ACCESS_READ);
        }
        return add_rm_operand(decoder, &modrm, memory_bits, 1)
            && set_last_operand_access(
                   decoder, CDISASM_OPERAND_ACCESS_WRITE)
            && add_bnd_register_operand_access(
                   decoder, modrm.reg, CDISASM_OPERAND_ACCESS_READ);
    }
    return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

/* VIA PadLock exposes a small set of fixed, operandless instructions in the
 * otherwise-reserved 0F A6/A7 rows.  They are not represented by the legacy
 * descriptor tables, so keep the byte-level ownership here.  The ModRM byte
 * is part of the opcode (all forms use mod=3); no register operand is
 * architecturally encoded despite the ModRM-shaped byte. */
static int decode_via_padlock(x86_decoder *decoder, uint8_t opcode)
{
    uint8_t modrm_byte;
#if USE_EXTRA_OPCODES
    x86_modrm modrm;
#endif
    cdisasm_x86_name_id name_id = CDISASM_X86_NAME_NONE;
    cdisasm_x86_form_id form_id = 0;
    cdisasm_x86_group_id group_id = CDISASM_X86_GROUP_VIA_PADLOCK_AES;

    if (opcode != UINT8_C(0xa6) && opcode != UINT8_C(0xa7)) {
        return -1;
    }

    /* PadLock encodings are fixed legacy forms: REP is mandatory for every
     * operation except XSTORE, and other legacy/REX selectors are reserved. */
    if (decoder->lock_prefix || decoder->operand_override
        || decoder->address_override || decoder->segment_prefix != 0
        || decoder->rex_present || decoder->rex2_present
        || decoder->repeat_prefix == UINT8_C(0xf2)) {
        return decoder_fail(decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (decoder->position >= decoder->code_size) {
        return decoder_fail(decoder, CDISASM_STATUS_TRUNCATED);
    }
    modrm_byte = decoder->code[decoder->position];

    if (opcode == UINT8_C(0xa6)) {
        switch (modrm_byte) {
            case UINT8_C(0xc0):
                name_id = CDISASM_X86_NAME_REP_MONTMUL;
                form_id = UINT16_C(1409);
                group_id = CDISASM_X86_GROUP_VIA_PADLOCK_MONTMUL;
                break;
            case UINT8_C(0xc8):
                name_id = CDISASM_X86_NAME_REP_XSHA1;
                form_id = UINT16_C(1426);
                group_id = CDISASM_X86_GROUP_VIA_PADLOCK_SHA;
                break;
            case UINT8_C(0xd0):
                name_id = CDISASM_X86_NAME_REP_XSHA256;
                form_id = UINT16_C(1427);
                group_id = CDISASM_X86_GROUP_VIA_PADLOCK_SHA;
                break;
            default:
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    } else {
        switch (modrm_byte) {
            case UINT8_C(0xc0):
                if (decoder->repeat_prefix == 0) {
                    name_id = CDISASM_X86_NAME_XSTORE;
                    form_id = UINT16_C(2027);
                    group_id = CDISASM_X86_GROUP_VIA_PADLOCK_RNG;
                } else if (decoder->repeat_prefix == UINT8_C(0xf3)) {
                    name_id = CDISASM_X86_NAME_REP_XSTORE;
                    form_id = UINT16_C(1428);
                    group_id = CDISASM_X86_GROUP_VIA_PADLOCK_RNG;
                } else {
                    return decoder_fail(
                        decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
                }
                break;
            case UINT8_C(0xc8):
                name_id = CDISASM_X86_NAME_REP_XCRYPTECB;
                form_id = UINT16_C(1424);
                break;
            case UINT8_C(0xd0):
                name_id = CDISASM_X86_NAME_REP_XCRYPTCBC;
                form_id = UINT16_C(1421);
                break;
            case UINT8_C(0xd8):
                name_id = CDISASM_X86_NAME_REP_XCRYPTCTR;
                form_id = UINT16_C(1423);
                break;
            case UINT8_C(0xe0):
                name_id = CDISASM_X86_NAME_REP_XCRYPTCFB;
                form_id = UINT16_C(1422);
                break;
            case UINT8_C(0xe8):
                name_id = CDISASM_X86_NAME_REP_XCRYPTOFB;
                form_id = UINT16_C(1425);
                break;
            default:
                return decoder_fail(
                    decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (name_id != CDISASM_X86_NAME_XSTORE
            && decoder->repeat_prefix != UINT8_C(0xf3)) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    if (name_id != CDISASM_X86_NAME_XSTORE
        && decoder->repeat_prefix != UINT8_C(0xf3)) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if !USE_EXTRA_OPCODES
    (void)name_id;
    (void)form_id;
    (void)group_id;
    return decoder_fail(
        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    if (decoder->cpu_id != CDISASM_CPU_X86) {
        return decoder_fail(
            decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    if (!decode_modrm(decoder, &modrm)) {
        return 0;
    }
    decoder->name_id = name_id;
    decoder->form_id = form_id;
    /* The byte is consumed as a structural ModRM, but PadLock has no
     * explicit operands.  The late group is attached in
     * add_effective_encoding_groups because it lies beyond the compact
     * two-word optional-group capability masks. */
    (void)group_id;
    return 1;
#endif
}

static int decode_two_byte(x86_decoder *decoder)
{
    uint8_t opcode;
    const x86_opcode_descriptor *descriptor;
    unsigned int bits;
    int simd_result;

    if (!read_u8(decoder, &opcode)) {
        return 0;
    }
    ++decoder->encoding.opcode_size;
    {
        int padlock_result = decode_via_padlock(decoder, opcode);

        if (padlock_result >= 0) {
            return padlock_result;
        }
    }
    if (opcode == UINT8_C(0x1c)) {
        return decode_cldemote_nop_row(decoder);
    }
    if (opcode == UINT8_C(0x18)) {
        return decode_prefetch_row(decoder);
    }
    if ((opcode == UINT8_C(0x19) || opcode == UINT8_C(0x1d))
        && decoder->repeat_prefix == 0
        && !decoder->operand_override) {
        x86_modrm modrm;
        unsigned int nop_bits = decoder->mode == CDISASM_MODE_64
            ? 32u : decoder->operand_bits;

        if (!decode_modrm(decoder, &modrm)) {
            return 0;
        }
        if (decoder->lock_prefix || decoder->rex2_present) {
            return decoder_fail(
                decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        decoder->name_id = CDISASM_X86_NAME_NOP;
        decoder_require_caps(decoder, X86_CAP_P6);
        return add_rm_operand(decoder, &modrm, nop_bits, 1)
            && set_last_operand_access(
                decoder, CDISASM_OPERAND_ACCESS_READ)
            && add_register_operand_access(
                decoder, modrm.reg, nop_bits,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (opcode == UINT8_C(0x1a) || opcode == UINT8_C(0x1b)) {
        return decode_mpx_row(decoder, opcode);
    }
    /* 0F AE is a mixed system/SIMD row.  The unified handler owns every
     * mandatory-prefix selector plus the legacy MXCSR/SFENCE forms so the
     * unprefixed CLFLUSH /7 memory form cannot be swallowed by the old SIMD
     * descriptor before system dispatch. */
    if (opcode == UINT8_C(0xae)) {
        return decode_system_0fae(decoder);
    }
    if (opcode == UINT8_C(0x2b) || opcode == UINT8_C(0xe7)) {
        return decode_non_temporal_simd_store(decoder, opcode);
    }
    if (opcode == UINT8_C(0xf0)) {
        return decode_lddqu_legacy(decoder, opcode);
    }
    simd_result = decode_legacy_simd_map(
        decoder,
        x86_0f_simd_map,
        sizeof(x86_0f_simd_map) / sizeof(x86_0f_simd_map[0]),
        opcode);
    if (simd_result >= 0) {
        return simd_result;
    }
    descriptor = &x86_0f_map[opcode];
    decoder->groups |= descriptor->groups;

    switch ((x86_decode_form)descriptor->form) {
        case X86_DECODE_FORM_INVALID:
            return decoder_fail(
                decoder,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        case X86_DECODE_FORM_UNSUPPORTED:
            return decoder_fail(
                decoder,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        case X86_DECODE_FORM_FIXED:
            if (descriptor->name_id == CDISASM_X86_NAME_NONE) {
                return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
            }
            if (descriptor->name_id == CDISASM_X86_NAME_RSM) {
                if (decoder->rex2_present) {
                    return decoder_fail(
                        decoder, CDISASM_STATUS_INVALID_INSTRUCTION);
                }
                decoder_require_caps(decoder, X86_CAP_80486);
            }
            /* F3 0F 09 is WBNOINVD only on processors that advertise it.
             * On older processors F3 remains an ignored legacy prefix and
             * the same bytes retain the WBINVD interpretation. */
            if (descriptor->name_id == CDISASM_X86_NAME_WBINVD
                && decoder->repeat_prefix == UINT8_C(0xf3)
                && decoder_has_caps(decoder, X86_CAP_WBNOINVD)) {
#if !USE_EXTRA_OPCODES
                return decoder_fail(
                    decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
                decoder->name_id = CDISASM_X86_NAME_WBNOINVD;
                decoder_require_caps(decoder, X86_CAP_WBNOINVD);
                return 1;
#endif
            }
            decoder->name_id = descriptor->name_id;
            return 1;
        case X86_DECODE_FORM_SYSTEM_GROUP6: {
            static const cdisasm_x86_name_id name_ids[8] = {
                CDISASM_X86_NAME_SLDT, CDISASM_X86_NAME_STR,
                CDISASM_X86_NAME_LLDT, CDISASM_X86_NAME_LTR,
                CDISASM_X86_NAME_VERR, CDISASM_X86_NAME_VERW,
                CDISASM_X86_NAME_NONE, CDISASM_X86_NAME_NONE
            };
            x86_modrm modrm;
            unsigned int system_bits;

            if (!decode_modrm(decoder, &modrm)) {
                return 0;
            }
            /* LKGS occupies the mandatory-F2 /6 sub-row of 0F 00 in
             * long mode.  The hand decoder owns the surrounding Group-6
             * system forms; leave this late allocation to the generated
             * descriptor path so its CPU/flag admission and operand recipe
             * remain data-driven. */
            if (modrm.reg3 == 6
                && decoder->mode == CDISASM_MODE_64
                && decoder->repeat_prefix == UINT8_C(0xf2)) {
                return decoder_fail(
                    decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
            if (modrm.reg3 >= 6) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = name_ids[modrm.reg3];
            if (modrm.reg3 == 2 || modrm.reg3 == 3) {
                decoder->groups |= CDISASM_GROUP_PRIVILEGED;
            }
            system_bits = modrm.reg3 <= 1 && modrm.is_register
                ? decoder->operand_bits
                : 16u;
            return add_rm_operand(decoder, &modrm, system_bits, 1);
        }
        case X86_DECODE_FORM_SYSTEM_GROUP7: {
            static const cdisasm_x86_name_id name_ids[8] = {
                CDISASM_X86_NAME_SGDT, CDISASM_X86_NAME_SIDT,
                CDISASM_X86_NAME_LGDT, CDISASM_X86_NAME_LIDT,
                CDISASM_X86_NAME_SMSW, CDISASM_X86_NAME_NONE,
                CDISASM_X86_NAME_LMSW, CDISASM_X86_NAME_INVLPG
            };
            x86_modrm modrm;
            unsigned int memory_bits;

            if (!decode_modrm(decoder, &modrm)) {
                return 0;
            }
            {
                int cet_result = decode_cet_group7(decoder, &modrm);

                if (cet_result >= 0) {
                    return cet_result;
                }
            }
            if (modrm.is_register) {
                int decoded =
                    decode_fixed_virtualization_system(decoder, &modrm);

                if (decoded || decoder->error != CDISASM_STATUS_OK) {
                    return decoded;
                }
                /* TDX SEAMCALL/SEAMOPS/SEAMRET/TDCALL are the 66-prefixed
                 * /1 fixed Group-7 allocations.  Keep the structural owner
                 * here, but let the generated catalog select the exact
                 * mnemonic and ISA-set bit. */
                if (decoder->mode == CDISASM_MODE_64
                    && decoder->operand_override
                    && decoder->repeat_prefix == 0
                    && modrm.reg3 == 1
                    && modrm.rm3 >= 4 && modrm.rm3 <= 7) {
#if USE_EXTRA_OPCODES
                    /* TDX fixed Group-7 leaves are architecturally
                     * operandless.  Keep the mode/prefix discriminator here,
                     * then assign the stable IFORM/name identity so the
                     * generated fallback does not turn these privileged
                     * system leaves into generic unsupported bytes. */
                    static const cdisasm_x86_name_id tdx_names[8] = {
                        CDISASM_X86_NAME_NONE,
                        CDISASM_X86_NAME_NONE,
                        CDISASM_X86_NAME_NONE,
                        CDISASM_X86_NAME_NONE,
                        CDISASM_X86_NAME_TDCALL,
                        CDISASM_X86_NAME_SEAMRET,
                        CDISASM_X86_NAME_SEAMOPS,
                        CDISASM_X86_NAME_SEAMCALL
                    };
                    static const cdisasm_x86_form_id tdx_forms[8] = {
                        0, 0, 0, 0,
                        UINT16_C(1452), UINT16_C(1437),
                        UINT16_C(1436), UINT16_C(1435)
                    };

                    decoder->name_id = tdx_names[modrm.rm3];
                    decoder->form_id = tdx_forms[modrm.rm3];
                    decoder->groups |= CDISASM_GROUP_PRIVILEGED;
                    return 1;
#else
                    return decoder_fail(
                        decoder, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
            /*
             * Most mod=3 values are separate system opcodes; /4 and /6
             * retain their ordinary SMSW/LMSW register forms.
             */
            if (modrm.is_register
                && modrm.reg3 != 4
                && modrm.reg3 != 6) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
            if (modrm.reg3 == 5
                || name_ids[modrm.reg3] == CDISASM_X86_NAME_NONE) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = name_ids[modrm.reg3];
            if (modrm.reg3 == 2
                || modrm.reg3 == 3
                || modrm.reg3 == 6
                || modrm.reg3 == 7) {
                decoder->groups |= CDISASM_GROUP_PRIVILEGED;
            }
            if (modrm.reg3 <= 3) {
                memory_bits = decoder->mode == CDISASM_MODE_64
                    ? 80u
                    : 48u;
            } else if (modrm.reg3 == 4 && modrm.is_register) {
                memory_bits = decoder->operand_bits;
            } else {
                memory_bits = 16u;
            }
            return add_rm_operand(decoder, &modrm, memory_bits, 1);
        }
        case X86_DECODE_FORM_SELECTOR_QUERY:
            return decode_selector_query(decoder, descriptor->name_id);
        case X86_DECODE_FORM_LOADALL_SYSCALL:
            if (decoder->cpu_id == CDISASM_CPU_80286) {
                decoder->name_id = CDISASM_X86_NAME_LOADALL286;
                decoder->groups |= CDISASM_GROUP_PRIVILEGED;
                decoder_require_caps(decoder, X86_CAP_80286);
            } else {
                decoder->name_id = CDISASM_X86_NAME_SYSCALL;
                decoder->groups |= CDISASM_GROUP_INTERRUPT;
            }
            return 1;
        case X86_DECODE_FORM_LOADALL_SYSRET:
            if (decoder->cpu_id == CDISASM_CPU_80386) {
                decoder->name_id = CDISASM_X86_NAME_LOADALL;
                decoder_require_caps(decoder, X86_CAP_80386);
            } else {
                decoder->name_id = CDISASM_X86_NAME_SYSRET;
                decoder->groups |= CDISASM_GROUP_INTERRUPT_RETURN;
            }
            return 1;
        case X86_DECODE_FORM_PREFETCH:
            return decode_3dnow_prefetch(decoder);
        case X86_DECODE_FORM_3DNOW:
            return decode_3dnow(decoder);
        case X86_DECODE_FORM_ENDBR:
            return decode_endbr(decoder);
        case X86_DECODE_FORM_SYSTEM_0FAE:
            return decode_system_0fae(decoder);
        case X86_DECODE_FORM_MOVNTI:
            return decode_movnti(decoder);
        case X86_DECODE_FORM_HINT_NOP: {
            x86_modrm modrm;
            unsigned int nop_bits = decoder->mode == CDISASM_MODE_64
                ? (decoder->operand_override ? 16u : 32u)
                : decoder->operand_bits;

            if (!decode_modrm(decoder, &modrm)) {
                return 0;
            }
            if (modrm.reg3 != 0) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            decoder_require_caps(decoder, X86_CAP_P6);
            return add_rm_operand(decoder, &modrm, nop_bits, 1);
        }
        case X86_DECODE_FORM_CONTROL_DEBUG_MOVE:
            return decode_control_debug_move(
                decoder,
                descriptor->argument);
        case X86_DECODE_FORM_CMOVCC:
            return decode_cmovcc(decoder, descriptor->argument);
        case X86_DECODE_FORM_JCC_NEAR:
            decoder_require_caps(decoder, X86_CAP_80386);
            return decode_jcc(
                decoder,
                descriptor->argument,
                decoder->mode == CDISASM_MODE_64
                    ? 32u
                    : decoder->operand_bits);
        case X86_DECODE_FORM_SETCC:
            return decode_setcc(decoder, descriptor->argument);
        case X86_DECODE_FORM_BSWAP:
            bits = decoder->mode == CDISASM_MODE_64
                    && (decoder->rex & 8u) != 0
                ? 64u
                : 32u;
            if (decoder->operand_override && bits == 32) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            return add_register_operand(
                decoder,
                descriptor->argument
                    + ((decoder->rex & 1u) ? 8u : 0u),
                bits);
        case X86_DECODE_FORM_VMX_READ_WRITE:
            return decode_vmx_read_write(decoder, opcode);
        case X86_DECODE_FORM_SEGMENT_STACK:
            return decode_push_pop_fs_gs(decoder, opcode);
        case X86_DECODE_FORM_BIT_REGISTER:
            return decode_bit_register(
                decoder,
                descriptor->name_id,
                descriptor->argument != 0);
        case X86_DECODE_FORM_DOUBLE_SHIFT:
            return decode_double_shift(decoder, opcode);
        case X86_DECODE_FORM_BINARY_RM_REG:
            bits = descriptor->argument == 0
                ? decoder->operand_bits
                : descriptor->argument;
            if (descriptor->name_id == CDISASM_X86_NAME_IMUL) {
                decoder_require_caps(decoder, X86_CAP_80386);
                return decode_two_byte_binary(
                    decoder,
                    descriptor->name_id,
                    bits);
            }
            return decode_binary_rm_reg(
                decoder,
                descriptor->name_id,
                bits,
                0,
                1);
        case X86_DECODE_FORM_SEGMENT_LOAD: {
            x86_modrm modrm;
            unsigned int memory_bits;

            if (!decode_modrm(decoder, &modrm)) {
                return 0;
            }
            if (modrm.is_register) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            decoder->name_id = descriptor->name_id;
            memory_bits = decoder->operand_bits == 16
                ? 32u
                : decoder->operand_bits == 32
                    ? 48u
                    : 80u;
            return add_register_operand(
                    decoder,
                    modrm.reg,
                    decoder->operand_bits)
                && add_rm_operand(decoder, &modrm, memory_bits, 1);
        }
        case X86_DECODE_FORM_MOVX:
            return decode_movx(decoder, opcode);
        case X86_DECODE_FORM_POPCNT:
            if (decoder->repeat_prefix != 0xf3) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            return decode_two_byte_binary(
                decoder,
                descriptor->name_id,
                decoder->operand_bits);
        case X86_DECODE_FORM_UD_RM:
            if (descriptor->argument == 0) {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INTERNAL_ERROR);
            }
            if (descriptor->name_id == CDISASM_X86_NAME_UD0) {
                if (!decoder_has_caps(decoder, X86_CAP_UD0)) {
                    return decoder_fail(
                        decoder,
                        CDISASM_STATUS_INVALID_INSTRUCTION);
                }
                decoder_require_caps(decoder, X86_CAP_UD0);
                if (cpu_uses_short_ud0(decoder->cpu_id)) {
                    decoder->name_id = descriptor->name_id;
                    return 1;
                }
            } else if (descriptor->name_id == CDISASM_X86_NAME_UD1) {
                if (!decoder_has_caps(decoder, X86_CAP_UD1)) {
                    return decoder_fail(
                        decoder,
                        CDISASM_STATUS_INVALID_INSTRUCTION);
                }
                decoder_require_caps(decoder, X86_CAP_UD1);
            } else {
                return decoder_fail(
                    decoder,
                    CDISASM_STATUS_INTERNAL_ERROR);
            }
            return decode_undefined_rm(
                decoder,
                descriptor->name_id,
                descriptor->argument);
        case X86_DECODE_FORM_GROUP8:
            return decode_group8(decoder);
        case X86_DECODE_FORM_BIT_SCAN_ALIAS:
            if (descriptor->argument == 0) {
                return decode_two_byte_binary(
                    decoder,
                    decoder->repeat_prefix == 0xf3
                            && decoder_has_caps(decoder, X86_CAP_BMI1)
                        ? CDISASM_X86_NAME_TZCNT
                        : CDISASM_X86_NAME_BSF,
                    decoder->operand_bits);
            }
            return decode_two_byte_binary(
                decoder,
                decoder->repeat_prefix == 0xf3
                        && decoder_has_caps(decoder, X86_CAP_LZCNT)
                    ? CDISASM_X86_NAME_LZCNT
                    : CDISASM_X86_NAME_BSR,
                decoder->operand_bits);
        case X86_DECODE_FORM_VMX_POINTER:
            return decode_vmx_pointer(decoder);
        case X86_DECODE_FORM_ESCAPE_0F38:
            return decode_three_byte_map(decoder, x86_0f38_map);
        case X86_DECODE_FORM_ESCAPE_0F3A:
            return decode_three_byte_map(decoder, x86_0f3a_map);
        default:
            return decoder_fail(decoder, CDISASM_STATUS_INTERNAL_ERROR);
    }
}
